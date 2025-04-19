# Azure DNS Enumeration Tools

This repository contains tools for enumerating Azure DNS services. These tools are designed for security professionals, penetration testers, and system administrators who need to assess the security of Azure environments through DNS reconnaissance.

## Overview

This repository includes two primary tools:

1. **Public DNS Enumeration Tool** - Discovers Azure resources using only publicly available DNS information, without requiring any authentication.
2. **Authenticated DNS Enumeration Tool** - Utilizes the Azure SDK to provide comprehensive DNS information when you have valid Azure credentials.

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/azure-dns-enum.git
cd azure-dns-enum

# Install dependencies
pip install -r requirements.txt
```

## Tools

### 1. Public DNS Enumeration Tool

The `azure_public_dns_enum.py` script performs DNS enumeration without requiring Azure authentication.

#### Features:
- Scans common Azure domains (azurewebsites.net, blob.core.windows.net, etc.)
- Discovers subdomains using brute-force techniques
- Identifies Azure service types
- Detects publicly accessible web services
- Multi-threaded for efficient scanning

#### Usage:
```bash
python azure_public_dns_enum.py [--domain DOMAIN] [--wordlist WORDLIST] [--output OUTPUT_FILE] [--threads THREADS]
```

#### Examples:
```bash
# Basic scan of common Azure domains
python azure_public_dns_enum.py

# Scan a specific domain
python azure_public_dns_enum.py --domain contoso.azurewebsites.net

# Use a custom subdomain wordlist
python azure_public_dns_enum.py --wordlist subdomains.txt

# Save results to JSON
python azure_public_dns_enum.py --output results.json

# Increase concurrency
python azure_public_dns_enum.py --threads 20
```

### 2. Authenticated DNS Enumeration Tool

The `azure_dns_enum.py` script provides comprehensive DNS information using the Azure SDK when you have valid Azure credentials.

#### Features:
- Lists all DNS zones in accessible subscriptions
- Enumerates all record types (A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT, CAA)
- Provides detailed record information
- Outputs in various formats (text, JSON, CSV)

#### Authentication:
The tool uses Azure's authentication libraries and supports:
- Azure CLI authentication (`az login`)
- Environment variables
- Managed Identity
- Service Principal

#### Usage:
```bash
python azure_dns_enum.py [--subscription SUBSCRIPTION_ID] [--output OUTPUT_FILE] [--format {json,csv,text}]
```

#### Examples:
```bash
# Scan all accessible subscriptions
python azure_dns_enum.py

# Scan a specific subscription
python azure_dns_enum.py --subscription "your-subscription-id"

# Export results to JSON
python azure_dns_enum.py --format json --output dns_results.json

# Export results to CSV
python azure_dns_enum.py --format csv --output dns_results.csv
```

## Use Cases

- **Security Assessments**: Identify potentially exposed Azure resources
- **Attack Surface Mapping**: Discover all publicly accessible endpoints
- **Security Monitoring**: Track and monitor your organization's Azure DNS footprint
- **Penetration Testing**: Gather intelligence during the reconnaissance phase

## Ethical Use

These tools are provided for legitimate security testing and assessment purposes only. Always ensure you have proper authorization before performing any security testing. Unauthorized scanning may violate:

1. Azure's Terms of Service
2. Computer Misuse/Fraud legislation
3. Privacy and data protection regulations

## Requirements

### Public DNS Enumeration Tool:
- Python 3.6+
- dnspython
- requests
- tqdm

### Authenticated DNS Enumeration Tool:
- Python 3.6+
- azure-identity
- azure-mgmt-dns
- azure-mgmt-subscription
- tabulate

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

These tools are provided as-is without any warranty. The author is not responsible for any misuse or damage caused by these tools. Use at your own risk.
