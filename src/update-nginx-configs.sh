#!/bin/bash

# Exit on any error
set -e

# Backup directory
BACKUP_DIR="/root/nginx-configs-backup-$(date +%Y%m%d_%H%M%S)"
SITES_AVAILABLE="/etc/nginx/sites-available"

# Create backup directory
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Backup all current configurations
echo "Backing up current NGINX configurations..."
cp -r "$SITES_AVAILABLE"/* "$BACKUP_DIR/"
echo "Backup completed in $BACKUP_DIR"

# Counter for modified files
MODIFIED_COUNT=0

# Update each configuration file
for config in "$SITES_AVAILABLE"/*; do
    if [ -f "$config" ]; then
        echo "Processing $config..."
        
        # Check if CF-Connecting-IP header is already present
        if ! grep -q "proxy_set_header CF-Connecting-IP" "$config"; then
            # Add CF-Connecting-IP header after X-Forwarded-Proto
            sed -i '/proxy_set_header X-Forwarded-Proto/a \ \ \ \ \ \ \ \ proxy_set_header CF-Connecting-IP $remote_addr;' "$config"
            ((MODIFIED_COUNT++))
            echo "Modified $config"
        else
            echo "CF-Connecting-IP header already present in $config, skipping..."
        fi
    fi
done

# Test NGINX configuration
echo "Testing NGINX configuration..."
if nginx -t; then
    echo "NGINX configuration test successful"
    
    # Reload NGINX
    echo "Reloading NGINX..."
    systemctl reload nginx
    
    echo "Successfully completed!"
    echo "Modified $MODIFIED_COUNT configuration files"
    echo "Backup saved in $BACKUP_DIR"
else
    echo "ERROR: NGINX configuration test failed!"
    echo "Rolling back changes..."
    
    # Restore from backup
    cp -r "$BACKUP_DIR"/* "$SITES_AVAILABLE/"
    
    echo "Changes rolled back. Original configurations restored."
    echo "Please check your NGINX configurations manually."
    exit 1
fi