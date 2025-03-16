import express, { Express, Request, Response, NextFunction } from "express";
import { exec } from "child_process";
import fs from "fs/promises";
import dotenv from "dotenv";
import { CronJob } from "cron";

dotenv.config();

const app = express();
app.use(express.json());

function slowEquals(a: string, b: string): boolean {
  if (!a || !b || a.length !== b.length) return false;

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

const authenticateToken = (
  req: Request,
  res: Response,
  next: NextFunction
): any => {
  const authHeader = req.headers["authorization"];
  const token = authHeader?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }
  if (!slowEquals(token, process.env.ADMIN_TOKEN as string)) {
    return res.status(403).json({ error: "Invalid token" });
  }
  next();
};

const isValidDomain = (domain: string) => {
  const pattern = /^[a-zA-Z0-9][a-zA-Z0-9-_.]+[a-zA-Z0-9]$/;
  return pattern.test(domain) && domain.length < 255;
};

const execCommand = (command: string): Promise<string> => {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
};

// Initial HTTP-only config for Certbot verification
const generateInitialConfig = (domain: string, subdomain: string) => `
server {
    listen 80;
    server_name ${domain};
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass https://${subdomain}.orbiter.website$request_uri;
        proxy_set_header Host ${subdomain}.orbiter.website;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
    }
}`;

// Final config with SSL
const generateFinalConfig = (domain: string, subdomain: string) => `
server {
    listen 80;
    server_name ${domain};
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl http2;
    server_name ${domain};
    resolver 8.8.8.8 valid=30s ipv6=off;

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    location / {
        proxy_pass https://${subdomain}.orbiter.website$request_uri;
        proxy_set_header Host ${subdomain}.orbiter.website;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
    }
}`;

const needsRenewal = async (domain: string): Promise<boolean> => {
  try {
    const result = await execCommand(
      `certbot certificates --cert-name ${domain}`
    );
    // Parse the expiry date from the output
    const expiryMatch = result.match(/VALID: (\d+) days/);
    if (expiryMatch && expiryMatch[1]) {
      const daysRemaining = parseInt(expiryMatch[1], 10);
      return daysRemaining <= 30; // Only renew if 30 days or less remaining
    }
    return false; // If we can't determine, assume no renewal needed
  } catch (error) {
    console.log(`Error checking cert expiry for ${domain}:`, error);
    return false; // If check fails, assume no renewal needed
  }
};

const getCertInfo = async (domain: string): Promise<any> => {
  try {
    const result = await execCommand(
      `certbot certificates --cert-name ${domain}`
    );

    // Parse expiry date
    const expiryMatch = result.match(
      /Expiry Date: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/
    );
    const daysMatch = result.match(/VALID: (\d+) days/);

    if (expiryMatch && expiryMatch[1] && daysMatch && daysMatch[1]) {
      return {
        domain,
        expiryDate: expiryMatch[1],
        daysRemaining: parseInt(daysMatch[1], 10),
        needsRenewal: parseInt(daysMatch[1], 10) <= 30,
      };
    }

    return {
      domain,
      expiryDate: "Unknown",
      daysRemaining: -1,
      needsRenewal: false,
      error: "Could not parse certificate information",
    };
  } catch (error: any) {
    return {
      domain,
      expiryDate: "Unknown",
      daysRemaining: -1,
      needsRenewal: false,
      error: error.message,
    };
  }
};

const renewCert = async (
  domain: string,
  forceRenewal = false
): Promise<any> => {
  console.log(`Checking certificate for ${domain}`);

  try {
    // Check if domain config exists
    await fs.access(`/etc/nginx/sites-available/${domain}`);

    // Check if renewal is needed
    const shouldRenew = forceRenewal || (await needsRenewal(domain));

    if (!shouldRenew) {
      console.log(`Certificate for ${domain} doesn't need renewal yet`);
      return {
        status: "skipped",
        message: `Certificate for ${domain} doesn't need renewal yet`,
      };
    }

    console.log(`Renewing certificate for ${domain}`);

    // Ensure webroot directory exists
    await fs.mkdir("/var/www/certbot", { recursive: true });

    // Renew the certificate
    await execCommand(
      `certbot renew --cert-name ${domain} --non-interactive --webroot -w /var/www/certbot`
    );

    // Test and reload NGINX
    await execCommand("nginx -t");
    await execCommand("nginx -s reload");

    console.log(`Certificate for ${domain} renewed successfully`);
    return {
      status: "success",
      message: `Certificate for ${domain} renewed successfully`,
    };
  } catch (error: any) {
    console.error(`Error renewing certificate for ${domain}:`, error.message);
    return {
      status: "error",
      message: `Error renewing certificate: ${error.message}`,
    };
  }
};

const getAllConfiguredDomains = async (): Promise<string[]> => {
  try {
    const files = await fs.readdir("/etc/nginx/sites-available");
    // Filter out non-domain files if needed
    return files.filter(
      (file) =>
        !file.includes("default") && !file.startsWith(".") && file.includes(".")
    );
  } catch (error) {
    console.error("Error reading sites-available directory:", error);
    return [];
  }
};

const checkAndRenewAllCerts = async (): Promise<void> => {
  console.log("Starting daily certificate renewal check...");

  try {
    const domains = await getAllConfiguredDomains();
    console.log(`Found ${domains.length} domain(s) to check`);

    for (const domain of domains) {
      console.log(`Checking domain: ${domain}`);
      const result = await renewCert(domain);
      console.log(`Result for ${domain}:`, result.status);
    }

    console.log("Daily certificate renewal check completed");
  } catch (error) {
    console.error("Error during certificate renewal check:", error);
  }
};

const setupCronJob = () => {
  const job = new CronJob(
    "30 2 * * *",
    checkAndRenewAllCerts,
    null,
    true,
    "UTC"
  );
  console.log("Cron job scheduled to run daily at 2:30 AM UTC");
  return job;
};

let certRenewalJob: CronJob;

app.post(
  "/custom-domains",
  authenticateToken,
  async (req: Request, res: any) => {
    const { domain, subdomain } = req.body;

    if (
      !domain ||
      !subdomain ||
      !isValidDomain(domain) ||
      !isValidDomain(subdomain)
    ) {
      return res.status(400).json({ error: "Invalid domain or subdomain" });
    }

    try {
      // Create certbot webroot directory
      await fs.mkdir("/var/www/certbot", { recursive: true });

      // 1. First deploy HTTP-only config
      const configPath = `/etc/nginx/sites-available/${domain}`;
      await fs.writeFile(configPath, generateInitialConfig(domain, subdomain));

      // Setup symlink
      try {
        await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
      } catch (error) {
        // Ignore if doesn't exist
      }
      await fs.symlink(configPath, `/etc/nginx/sites-enabled/${domain}`);

      // Test and reload NGINX
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");

      // 2. Get SSL certificate
      await execCommand(
        `certbot certonly --webroot -w /var/www/certbot -d ${domain} --non-interactive --agree-tos --email launchorbiter@gmail.com --verbose`
      );

      // 3. Deploy final config with SSL
      await fs.writeFile(configPath, generateFinalConfig(domain, subdomain));

      // 4. Final test and reload
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");

      res.json({
        status: "success",
        message: "Domain configured successfully with SSL",
      });
    } catch (error: any) {
      // Cleanup on error
      try {
        await fs.unlink(`/etc/nginx/sites-available/${domain}`);
        await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
      } catch (cleanupError) {
        // Ignore cleanup errors
      }

      res.status(500).json({
        error: "Failed to configure domain",
        details: error.message,
      });
    }
  }
);

// Rest of the code remains the same...

app.delete(
  "/custom-domains",
  authenticateToken,
  async (req: Request, res: any) => {
    const { domain } = req.body;
    try {
      await execCommand(
        `certbot delete --cert-name ${domain} --non-interactive`
      );
      await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
      await fs.unlink(`/etc/nginx/sites-available/${domain}`);
      await execCommand("nginx -t");
      await execCommand("systemctl reload nginx");

      res.json({
        status: "success",
        message: "Domain configuration removed successfully",
      });
    } catch (error: any) {
      res.status(500).json({
        error: "Failed to remove domain configuration",
        details: error.message,
      });
    }
  }
);

app.post("/renew-cert", authenticateToken, async (req: Request, res: any) => {
  const { domain } = req.body;

  if (!domain || !isValidDomain(domain)) {
    return res.status(400).json({ error: "Invalid domain" });
  }

  try {
    await renewCert(domain);

    return res.json({
      status: "success",
      message: `SSL certificate for ${domain} renewed successfully`,
    });
  } catch (error: any) {
    return res.status(500).json({
      error: "Failed to renew certificate",
      details: error.message,
    });
  }
});

app.get("/certificates", authenticateToken, async (req: Request, res: any) => {
  try {
    const domains = await getAllConfiguredDomains();
    
    // Get info for all certificates in parallel
    const certInfoPromises = domains.map(domain => getCertInfo(domain));
    const certInfoResults = await Promise.all(certInfoPromises);
    
    return res.json({
      status: "success",
      certificates: certInfoResults
    });
  } catch (error: any) {
    return res.status(500).json({
      error: "Failed to get certificate information",
      details: error.message
    });
  }
});

app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "ok" });
});

app.listen(3000, () => {
  console.log("Domain manager listening on port 3000");
  certRenewalJob = setupCronJob();
});

process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: stopping cron job");
  if (certRenewalJob) {
    certRenewalJob.stop();
  }
  process.exit(0);
});
