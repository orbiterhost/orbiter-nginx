import express, { Express, Request, Response, NextFunction } from "express";
import { exec } from "child_process";
import fs from "fs/promises";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

// Domain mapping functions
const DOMAIN_MAPPING_FILE = '/etc/nginx/conf.d/domain_mappings.conf';

interface DomainMapping {
  domain: string;
  subdomain: string;
}

// Read current domain mappings
const readDomainMappings = async (): Promise<DomainMapping[]> => {
  try {
    const content = await fs.readFile(DOMAIN_MAPPING_FILE, 'utf8');
    const mappings: DomainMapping[] = [];
    
    // Parse the nginx map format
    const lines = content.split('\n');
    for (const line of lines) {
      const match = line.match(/^\s*"?([^"\s]+)"?\s+"?([^"\s]+)"?;?\s*$/);
      if (match && !line.includes('map') && !line.includes('{') && !line.includes('}')) {
        mappings.push({
          domain: match[1],
          subdomain: match[2]
        });
      }
    }
    
    return mappings;
  } catch (error) {
    // File doesn't exist yet, return empty array
    return [];
  }
};

// Write domain mappings to nginx map file
const writeDomainMappings = async (mappings: DomainMapping[]) => {
  const content = `# Auto-generated domain mappings
# This file maps customer domains to their corresponding subdomains

map $host $backend_subdomain {
    default "";
${mappings.map(m => `    "${m.domain}" "${m.subdomain}";`).join('\n')}
}

map $host $backend_host {
    default "";
${mappings.map(m => `    "${m.domain}" "${m.subdomain}.orbiter.website";`).join('\n')}
}`;

  await fs.writeFile(DOMAIN_MAPPING_FILE, content);
};

// Add a domain mapping
const addDomainMapping = async (domain: string, subdomain: string) => {
  const mappings = await readDomainMappings();
  
  // Remove existing mapping for this domain if it exists
  const filtered = mappings.filter(m => m.domain !== domain);
  
  // Add new mapping
  filtered.push({ domain, subdomain });
  
  await writeDomainMappings(filtered);
};

// Remove a domain mapping
const removeDomainMapping = async (domain: string) => {
  const mappings = await readDomainMappings();
  const filtered = mappings.filter(m => m.domain !== domain);
  await writeDomainMappings(filtered);
};

// Helper functions
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

// NEW PROXY-ONLY APPROACH
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
      // Add domain mapping to proxy system
      await addDomainMapping(domain, subdomain);
      
      // Reload nginx to pick up new mapping
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");

      res.json({
        status: "success",
        message: "Domain mapping added successfully",
        instructions: [
          `Point ${domain} CNAME record to proxy.orbiter.website`,
          "If you can't use CNAME, use A record to proxy.orbiter.website's IP",
          "Domain will be served through Cloudflare protection"
        ]
      });
    } catch (error: any) {
      // Cleanup on error
      try {
        await removeDomainMapping(domain);
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

app.delete(
  "/custom-domains",
  authenticateToken,
  async (req: Request, res: any) => {
    const { domain } = req.body;
    
    try {
      // Remove domain mapping
      await removeDomainMapping(domain);
      
      // Reload nginx
      await execCommand("nginx -t");
      await execCommand("nginx -s reload");

      res.json({
        status: "success",
        message: "Domain mapping removed successfully",
      });
    } catch (error: any) {
      res.status(500).json({
        error: "Failed to remove domain mapping",
        details: error.message,
      });
    }
  }
);

// View current mappings
app.get(
  "/custom-domains",
  authenticateToken,
  async (req: Request, res: any) => {
    try {
      const mappings = await readDomainMappings();
      res.json({
        status: "success",
        mappings: mappings
      });
    } catch (error: any) {
      res.status(500).json({
        error: "Failed to read domain mappings",
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