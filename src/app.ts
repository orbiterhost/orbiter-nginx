import express, { Express, Request, Response, NextFunction } from "express";
import { exec } from "child_process";
import fs from "fs/promises";
import dotenv from "dotenv";

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

// Updated config generation functions with bot protection

const generateInitialConfig = (domain: string, subdomain: string) => `
server {
    listen 80;
    server_name ${domain};
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log warn;
    
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        proxy_pass https://${subdomain}.orbiter.website$request_uri;
        proxy_set_header Host ${subdomain}.orbiter.website;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Original-Host $host;
        
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
    }
}`;

const generateFinalConfig = (domain: string, subdomain: string) => `
server {
    listen 80;
    server_name ${domain};
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log warn;
    
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

    # Detailed logging
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log warn;

    ssl_certificate /etc/letsencrypt/live/${domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${domain}/privkey.pem;

    # Block malicious scanners
    if ($blocked_scanner) {
        return 444;
    }
    
    # Block unwanted bots
    if ($blocked_bot) {
        return 444;
    }

    # Block WordPress attacks (customers don't use WordPress)
    location ~* /(wp-admin|wp-content|wp-login|phpmyadmin|xmlrpc\.php) {
        return 444;
    }
    
    # Block vulnerability scanning paths
    location ~* /(actuator|auth/realms|webdav) {
        return 444;
    }

    # Main location with rate limiting
    location / {
        limit_req zone=general burst=40 nodelay;
        
        proxy_pass https://${subdomain}.orbiter.website$request_uri;
        proxy_set_header Host ${subdomain}.orbiter.website;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Original-Host $host;
        
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
    }
}`;

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

app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "ok" });
});

app.listen(3000, () => {
  console.log("Domain manager listening on port 3000");
});
