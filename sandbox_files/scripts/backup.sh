#!/bin/bash
# Automated backup script for sandbox environment

BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="sandbox_backup_${DATE}.tar.gz"

echo "Starting backup at $(date)"

# Backup data directory
tar -czf "${BACKUP_DIR}/${BACKUP_FILE}" /sandbox_files/data /sandbox_files/documents

echo "Backup completed: ${BACKUP_FILE}"
