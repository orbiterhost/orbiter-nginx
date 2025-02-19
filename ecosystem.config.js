module.exports = {
    apps: [{
      name: "domain-manager",
      script: "./dist/app.js", // Assuming TypeScript compiled output
      watch: false,
      instances: 1,
      autorestart: true,
      max_memory_restart: "1G",
      env: {
        NODE_ENV: "production",
        ADMIN_TOKEN: process.env.ADMIN_TOKEN
        // Add other environment variables
      }
    }]
  };