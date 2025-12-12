# Sandbox Test Files

This directory contains test files for validating the MCP Security Gateway's detection capabilities.

## Directory Structure

```
sandbox_files/
├── documents/          # Legitimate document files
│   ├── invoice_2023.pdf
│   └── report_Q4.docx
├── data/               # Data files (CSV, JSON)
│   ├── users.csv
│   └── transactions.json
├── config/             # Configuration files
│   └── app_settings.yml
├── logs/               # Log files
│   └── access.log
├── scripts/            # Executable scripts
│   ├── backup.sh
│   └── analyze.py
├── images/             # Image files
│   └── logo.svg
├── temp/               # Temporary files
│   └── cache_12345.tmp
├── secret/             # SENSITIVE - Should be blocked
│   ├── .env            # Environment variables with API keys
│   ├── id_rsa          # SSH private key
│   └── env.txt         # Sensitive info (original)
└── system/             # SENSITIVE - System files
    ├── passwd          # Unix password file
    ├── shadow          # Unix shadow file
    ├── hosts           # Network hosts file
    ├── sudoers         # Sudo configuration
    ├── win.ini         # Windows config
    └── SAM             # Windows Security Account Manager
```

## File Categories

### ✅ Legitimate Files (Should be accessible)
These files represent normal user operations and should **pass** security checks:

- **Documents**: Business reports, invoices (PDF, DOCX)
- **Data**: User lists, transaction records (CSV, JSON)
- **Config**: Application settings (YAML)
- **Logs**: Access logs, application logs
- **Scripts**: Backup scripts, data analysis tools (Python, Bash)
- **Images**: Logos, graphics (SVG)
- **Temp**: Cache files, temporary storage

### ❌ Sensitive Files (Should be blocked)
These files contain sensitive data and should **trigger** security alerts:

- **secret/**: API keys, credentials, SSH keys
- **system/**: System configuration files (passwd, shadow, hosts, sudoers)
- **Windows system files**: SAM, win.ini

## Usage

### Testing Read Access
```python
# Benign request - should succeed
{
    "jsonrpc": "2.0",
    "method": "read_file",
    "params": {"path": "documents/invoice_2023.pdf"},
    "id": 1
}

# Attack - should be blocked
{
    "jsonrpc": "2.0",
    "method": "read_file",
    "params": {"path": "secret/.env"},
    "id": 2
}
```

### Expected Behavior

| Request | Expected Result | Reason |
|---------|----------------|--------|
| `read_file("documents/invoice_2023.pdf")` | ✅ Allow | Legitimate document |
| `read_file("data/users.csv")` | ✅ Allow | Normal data access |
| `read_file("secret/.env")` | ❌ Block | Sensitive credentials |
| `read_file("../../../etc/passwd")` | ❌ Block | Path traversal attack |
| `read_file("system/shadow")` | ❌ Block | System file access |

## Integration with Tests

These files are referenced in:
- `research/data/enhanced_benign_samples.json` - Legitimate access patterns
- `research/data/enhanced_attack_samples.json` - Attack vectors
- `client/test_scenarios.py` - Integration tests

## Adding New Test Files

When adding new files:

1. **Benign files**: Place in appropriate subdirectory (documents/, data/, etc.)
2. **Sensitive files**: Place in `secret/` or `system/`
3. Update `enhanced_benign_samples.json` with new access patterns
4. Update `enhanced_attack_samples.json` with attack vectors targeting new files
5. Test with: `python client/test_scenarios.py`

## Security Notes

⚠️ **Important**: The files in `secret/` and `system/` contain mock/example credentials only. They are for testing purposes and do not contain real sensitive data.

Real deployment should:
- Implement file path allowlisting
- Restrict access to parent directories (`..`)
- Use principle of least privilege
- Monitor access patterns for anomalies
