import express, { Express, Request, Response, NextFunction } from "express";
import { exec } from "child_process";
import fs from "fs/promises";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// Cloudflare API configuration
const CLOUDFLARE_API_BASE = 'https://api.cloudflare.com/client/v4';

interface CloudflareCustomHostname {
  id: string;
  hostname: string;
  ssl: {
    status: string;
    method: string;
    type: string;
  };
  status: string;
}

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

// Cloudflare for SaaS functions
async function createCloudflareCustomHostname(domain: string): Promise<CloudflareCustomHostname> {
  const response = await fetch(`${CLOUDFLARE_API_BASE}/zones/${process.env.CLOUDFLARE_ZONE_ID}/custom_hostnames`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      hostname: domain,
      ssl: {
        method: 'http',
        type: 'dv',
        settings: {
          http2: 'on',
          min_tls_version: '1.2',
          tls_1_3: 'on'
        }
      }
    })
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Cloudflare API error: ${error}`);
  }

  const result = await response.json();
  
  if (!result.success) {
    throw new Error(`Cloudflare error: ${result.errors?.[0]?.message || 'Unknown error'}`);
  }

  return result.result;
}

async function getCustomHostnameStatus(customHostnameId: string): Promise<CloudflareCustomHostname> {
  const response = await fetch(`${CLOUDFLARE_API_BASE}/zones/${process.env.CLOUDFLARE_ZONE_ID}/custom_hostnames/${customHostnameId}`, {
    headers: {
      'Authorization': `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
    }
  });
  
  const data = await response.json();
  return data.result;
}

async function waitForSSLValidation(customHostnameId: string, maxAttempts = 60): Promise<boolean> {
  console.log(`Waiting for SSL validation for custom hostname: ${customHostnameId}`);
  
  for (let i = 0; i < maxAttempts; i++) {
    const customHostname = await getCustomHostnameStatus(customHostnameId);
    const sslStatus = customHostname.ssl.status;
    
    console.log(`Attempt ${i + 1}: SSL Status = ${sslStatus}`);
    
    if (sslStatus === 'active') {
      console.log('SSL validation successful!');
      return true;
    }
    
    if (sslStatus === 'failed') {
      throw new Error('SSL validation failed');
    }
    
    // Wait 5 seconds before checking again
    await new Promise(resolve => setTimeout(resolve, 5000));
  }
  
  throw new Error('SSL validation timeout after 5 minutes');
}

async function deleteCloudflareCustomHostname(customHostnameId: string): Promise<void> {
  const response = await fetch(`${CLOUDFLARE_API_BASE}/zones/${process.env.CLOUDFLARE_ZONE_ID}/custom_hostnames/${customHostnameId}`, {
    method: 'DELETE',
    headers: {
      'Authorization': `Bearer ${process.env.CLOUDFLARE_API_TOKEN}`,
    }
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Failed to delete Cloudflare custom hostname: ${error}`);
  }
}

// Simplified nginx config generation (no SSL needed - Cloudflare handles it)
const generateCloudflareProxyConfig = (domain: string, subdomain: string) => `
server {
    listen 80;
    server_name ${domain};
    
    access_log /var/log/nginx/${domain}_access.log;
    error_log /var/log/nginx/${domain}_error.log warn;
    
    # Trust Cloudflare IPs and get real visitor IP
    real_ip_header CF-Connecting-IP;
    real_ip_recursive on;
    
    # Cloudflare IP ranges (add all current ranges)
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2a06:98c0::/29;
    set_real_ip_from 2c0f:f248::/32;

    # Block malicious scanners (your existing bot protection still applies)
    location ~* /(wp-admin|wp-content|wp-login|phpmyadmin|xmlrpc\.php) {
        return 444;
    }
    
    location ~* /(actuator|auth/realms|webdav) {
        return 444;
    }

    location / {
        # Rate limiting (can be more relaxed since Cloudflare handles DDoS)
        limit_req zone=flood burst=40 nodelay;
        
        proxy_pass https://${subdomain}.orbiter.website$request_uri;
        proxy_set_header Host ${subdomain}.orbiter.website;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Original-Host $host;
        
        # Pass through Cloudflare headers to your worker
        proxy_set_header CF-Ray $http_cf_ray;
        proxy_set_header CF-Visitor $http_cf_visitor;
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_set_header CF-IPCountry $http_cf_ipcountry;
        proxy_set_header CF-IPCity $http_cf_ipcity;
        
        proxy_ssl_server_name on;
        proxy_ssl_protocols TLSv1.2 TLSv1.3;
        proxy_ssl_verify off;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}`;

// Updated custom domains endpoint with Cloudflare for SaaS
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

    let cloudflareCustomHostname: CloudflareCustomHostname | null = null;

    try {
      console.log(`Setting up custom domain: ${domain} -> ${subdomain}.orbiter.website`);

      // 1. Create Cloudflare Custom Hostname (this handles SSL automatically)
      console.log('Creating Cloudflare custom hostname...');
      cloudflareCustomHostname = await createCloudflareCustomHostname(domain);
      console.log(`Custom hostname created with ID: ${cloudflareCustomHostname.id}`);

      // 2. Create simplified nginx config (no SSL needed, Cloudflare handles it)
      const configPath = `/etc/nginx/sites-available/${domain}`;
      await fs.writeFile(configPath, generateCloudflareProxyConfig(domain, subdomain));
      console.log('Nginx config written');

      // 3. Setup symlink
      try {
        await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
      } catch (error) {
        // Ignore if doesn't exist
      }
      await fs.symlink(configPath, `/etc/nginx/sites-enabled/${domain}`);
      console.log('Nginx symlink created');

      // 4. Test and reload NGINX
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");
      console.log('Nginx reloaded successfully');

      // 5. Wait for Cloudflare SSL validation (this can take a few minutes)
      console.log('Waiting for Cloudflare SSL validation...');
      await waitForSSLValidation(cloudflareCustomHostname.id);

      // 6. Get final status
      const finalStatus = await getCustomHostnameStatus(cloudflareCustomHostname.id);

      res.json({
        status: "success",
        message: "Domain configured successfully with Cloudflare protection",
        cloudflare: {
          custom_hostname_id: cloudflareCustomHostname.id,
          ssl_status: finalStatus.ssl.status,
          hostname_status: finalStatus.status
        },
        dns_instructions: {
          type: "CNAME",
          name: domain,
          target: cloudflareCustomHostname.hostname,
          note: "Customer needs to create this CNAME record in their DNS"
        }
      });

    } catch (error: any) {
      console.error('Domain setup error:', error);
      
      // Cleanup on error
      try {
        // Remove nginx config
        await fs.unlink(`/etc/nginx/sites-available/${domain}`);
        await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
        await execCommand("nginx -s reload");
        
        // Remove Cloudflare custom hostname if it was created
        if (cloudflareCustomHostname) {
          await deleteCloudflareCustomHostname(cloudflareCustomHostname.id);
        }
      } catch (cleanupError) {
        console.error('Cleanup error:', cleanupError);
      }

      res.status(500).json({
        error: "Failed to configure domain",
        details: error.message,
      });
    }
  }
);

// Updated delete endpoint with Cloudflare cleanup
app.delete(
  "/custom-domains",
  authenticateToken,
  async (req: Request, res: any) => {
    const { domain, cloudflare_custom_hostname_id } = req.body;
    
    if (!domain) {
      return res.status(400).json({ error: "Domain is required" });
    }

    try {
      console.log(`Removing custom domain: ${domain}`);

      // 1. Remove Cloudflare custom hostname (if ID provided)
      if (cloudflare_custom_hostname_id) {
        try {
          await deleteCloudflareCustomHostname(cloudflare_custom_hostname_id);
          console.log('Cloudflare custom hostname deleted');
        } catch (cfError) {
          console.error('Error deleting Cloudflare custom hostname:', cfError);
          // Continue with nginx cleanup even if Cloudflare fails
        }
      } else {
        console.log('No Cloudflare custom hostname ID provided, skipping CF cleanup');
      }

      // 2. Remove nginx configuration
      try {
        await fs.unlink(`/etc/nginx/sites-enabled/${domain}`);
        await fs.unlink(`/etc/nginx/sites-available/${domain}`);
        console.log('Nginx config files removed');
      } catch (nginxError) {
        console.error('Error removing nginx files:', nginxError);
        // Continue anyway
      }

      // 3. Test and reload nginx
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");
      console.log('Nginx reloaded');

      res.json({
        status: "success",
        message: "Domain configuration removed successfully",
      });

    } catch (error: any) {
      console.error('Domain removal error:', error);
      res.status(500).json({
        error: "Failed to remove domain configuration",
        details: error.message,
      });
    }
  }
);

// Health check endpoint
app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "ok" });
});

// Optional: Get status of a custom hostname
app.get(
  "/custom-domains/:domain/status",
  authenticateToken,
  async (req: Request, res: any) => {
    const { domain } = req.params;
    const { cloudflare_custom_hostname_id } = req.query;

    if (!cloudflare_custom_hostname_id) {
      return res.status(400).json({ error: "cloudflare_custom_hostname_id is required" });
    }

    try {
      const status = await getCustomHostnameStatus(cloudflare_custom_hostname_id as string);
      res.json({
        domain,
        cloudflare_status: status
      });
    } catch (error: any) {
      res.status(500).json({
        error: "Failed to get domain status",
        details: error.message,
      });
    }
  }
);

app.listen(3000, () => {
  console.log("Domain manager listening on port 3000");
  console.log("Cloudflare for SaaS integration enabled");
  
  // Check required environment variables
  const requiredEnvVars = ['ADMIN_TOKEN', 'CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ZONE_ID'];
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    console.error('Missing required environment variables:', missingVars);
    console.error('Please set these in your .env file');
  } else {
    console.log('All required environment variables are set');
  }
});