#!/usr/bin/env python3
"""
Azure Public DNS Enumeration Script

This script enumerates publicly available DNS information for Azure services
without requiring any Azure authentication. It uses standard DNS techniques
to discover information about Azure domains and services.

Usage:
    python azure_public_dns_enum.py [--domain DOMAIN] [--wordlist WORDLIST] [--output OUTPUT_FILE]

Requirements:
    pip install dnspython requests tqdm
"""

import argparse
import csv
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import requests
from tqdm import tqdm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Default Azure domains to check
AZURE_DOMAINS = [
    "azure.com",
    "azurewebsites.net",
    "cloudapp.azure.com",
    "cloudapp.net",
    "trafficmanager.net",
    "blob.core.windows.net",
    "file.core.windows.net",
    "queue.core.windows.net",
    "table.core.windows.net",
    "servicebus.windows.net",
    "database.windows.net",
    "azureedge.net",
    "search.windows.net",
    "azurecontainer.io",
    "azurecr.io",
    "redis.cache.windows.net",
    "azurehdinsight.net",
    "documents.azure.com",
    "core.windows.net"
]

# Default Azure common DNS prefixes to check
DEFAULT_SUBDOMAINS = [
    "api", "admin", "app", "apps", "auth", "cdn", "cloud", "cms", "dev", 
    "data", "demo", "docs", "events", "ftp", "git", "internal", "login", 
    "mail", "my", "portal", "remote", "secure", "smtp", "sql", "staging", 
    "support", "test", "vpn", "www", "web", "prod", "storage", "backup",
    "db", "database", "files", "file", "container", "containers", "vm", "vms"
]

class AzureDnsEnumerator:
    def __init__(self, domain=None, wordlist=None, output=None, threads=10):
        self.domains = [domain] if domain else AZURE_DOMAINS
        self.subdomains = self._load_wordlist(wordlist) if wordlist else DEFAULT_SUBDOMAINS
        self.output = output
        self.threads = threads
        self.results = []
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 2.0
        self.resolver.lifetime = 2.0
        
        # Commonly used public DNS servers
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']
    
    def _load_wordlist(self, wordlist_file):
        """Load subdomain wordlist from file"""
        try:
            with open(wordlist_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.error(f"Error loading wordlist: {str(e)}")
            logger.info("Falling back to default subdomain list")
            return DEFAULT_SUBDOMAINS
    
    def _check_subdomain(self, full_domain):
        """Check if a subdomain exists by attempting DNS resolution"""
        result = {
            "domain": full_domain,
            "a_records": [],
            "cname_records": [],
            "txt_records": [],
            "mx_records": [],
            "ns_records": [],
            "status": "Not Found"
        }
        
        try:
            # Check A records
            try:
                answers = self.resolver.resolve(full_domain, 'A')
                result["a_records"] = [str(rdata) for rdata in answers]
                result["status"] = "Found"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            
            # Check CNAME records
            try:
                answers = self.resolver.resolve(full_domain, 'CNAME')
                result["cname_records"] = [str(rdata.target) for rdata in answers]
                result["status"] = "Found"
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                pass
            
            # Only proceed with other lookups if the domain exists
            if result["status"] == "Found":
                # Check TXT records
                try:
                    answers = self.resolver.resolve(full_domain, 'TXT')
                    result["txt_records"] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                
                # Check MX records
                try:
                    answers = self.resolver.resolve(full_domain, 'MX')
                    result["mx_records"] = [f"{rdata.preference} {str(rdata.exchange)}" for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                
                # Check NS records
                try:
                    answers = self.resolver.resolve(full_domain, 'NS')
                    result["ns_records"] = [str(rdata) for rdata in answers]
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                    pass
                
                # Check if it appears to be an Azure resource
                result["is_azure"] = self._check_if_azure(result)
                
                # Try to determine the Azure service type
                result["azure_service"] = self._identify_azure_service(full_domain, result)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error checking {full_domain}: {str(e)}")
            return result
    
    def _check_if_azure(self, result):
        """Check if the DNS records indicate an Azure resource"""
        # Check CNAME records for Azure domains
        for cname in result.get("cname_records", []):
            if any(azure_domain in cname.lower() for azure_domain in AZURE_DOMAINS):
                return True
        
        # Check A records for Azure IP ranges
        # This is a simplified check - a comprehensive check would use Azure IP range data
        for ip in result.get("a_records", []):
            try:
                # Try to do a reverse lookup to see if it's an Azure IP
                reverse_name = dns.reversename.from_address(ip)
                reverse_records = self.resolver.resolve(reverse_name, "PTR")
                for rdata in reverse_records:
                    if any(azure_domain in str(rdata).lower() for azure_domain in AZURE_DOMAINS):
                        return True
            except:
                pass
        
        # Check TXT records for Azure verification strings
        for txt in result.get("txt_records", []):
            if "ms=" in txt or "azure-" in txt.lower() or "microsoft" in txt.lower():
                return True
        
        return False
    
    def _identify_azure_service(self, domain, result):
        """Try to identify the Azure service type based on domain and records"""
        domain_lower = domain.lower()
        
        # Check based on domain suffix
        if "azurewebsites.net" in domain_lower:
            return "App Service"
        elif "cloudapp.azure.com" in domain_lower or "cloudapp.net" in domain_lower:
            return "Cloud Service/VM"
        elif "trafficmanager.net" in domain_lower:
            return "Traffic Manager"
        elif "blob.core.windows.net" in domain_lower:
            return "Blob Storage"
        elif "file.core.windows.net" in domain_lower:
            return "File Storage"
        elif "queue.core.windows.net" in domain_lower:
            return "Queue Storage"
        elif "table.core.windows.net" in domain_lower:
            return "Table Storage"
        elif "servicebus.windows.net" in domain_lower:
            return "Service Bus"
        elif "database.windows.net" in domain_lower:
            return "SQL Database"
        elif "documents.azure.com" in domain_lower:
            return "Cosmos DB"
        elif "azureedge.net" in domain_lower:
            return "CDN"
        elif "search.windows.net" in domain_lower:
            return "Search Service"
        elif "azurecontainer.io" in domain_lower:
            return "Container Instance"
        elif "azurecr.io" in domain_lower:
            return "Container Registry"
        elif "redis.cache.windows.net" in domain_lower:
            return "Redis Cache"
        
        # Check based on CNAME records
        for cname in result.get("cname_records", []):
            cname_lower = cname.lower()
            if "azurewebsites.net" in cname_lower:
                return "App Service"
            elif "cloudapp.azure.com" in cname_lower or "cloudapp.net" in cname_lower:
                return "Cloud Service/VM"
            elif "trafficmanager.net" in cname_lower:
                return "Traffic Manager"
            elif "blob.core.windows.net" in cname_lower:
                return "Blob Storage"
            elif "azureedge.net" in cname_lower:
                return "CDN"
        
        return "Unknown Azure Service"
    
    def _check_azure_web_services(self, domain):
        """Try to determine if domain is pointing to a publicly accessible web service"""
        result = {"domain": domain, "web_service": False, "status_code": None, "server": None, "title": None}
        
        try:
            # Try both HTTP and HTTPS
            for protocol in ["https://", "http://"]:
                try:
                    url = f"{protocol}{domain}"
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
                    response = requests.get(url, headers=headers, timeout=5, allow_redirects=True, verify=False)
                    
                    result["web_service"] = True
                    result["status_code"] = response.status_code
                    result["server"] = response.headers.get('Server', '')
                    
                    # Try to extract title
                    if '<title>' in response.text.lower():
                        title_start = response.text.lower().find('<title>') + 7
                        title_end = response.text.lower().find('</title>', title_start)
                        if title_start > 0 and title_end > 0:
                            result["title"] = response.text[title_start:title_end].strip()
                    
                    # If successful with HTTPS, no need to try HTTP
                    break
                except:
                    continue
        except Exception as e:
            logger.debug(f"Error checking web service for {domain}: {str(e)}")
        
        return result
    
    def enumerate(self):
        """Enumerate Azure DNS information"""
        logger.info(f"Starting enumeration of {len(self.domains)} base Azure domains")
        logger.info(f"Using {len(self.subdomains)} subdomains for brute forcing")
        
        all_domains_to_check = []
        
        # Prepare all domain combinations to check
        for base_domain in self.domains:
            # Check the base domain itself
            all_domains_to_check.append(base_domain)
            
            # Check all subdomain combinations
            for subdomain in self.subdomains:
                full_domain = f"{subdomain}.{base_domain}"
                all_domains_to_check.append(full_domain)
        
        logger.info(f"Total {len(all_domains_to_check)} domains to check")
        
        # Use thread pool for faster execution
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all DNS check tasks
            future_to_domain = {executor.submit(self._check_subdomain, domain): domain for domain in all_domains_to_check}
            
            # Process results as they complete
            for future in tqdm(as_completed(future_to_domain), total=len(future_to_domain), desc="DNS Lookups"):
                domain = future_to_domain[future]
                try:
                    result = future.result()
                    if result["status"] == "Found":
                        self.results.append(result)
                except Exception as e:
                    logger.error(f"Error processing {domain}: {str(e)}")
        
        # Check for web services on found domains
        logger.info(f"Found {len(self.results)} active domains. Checking for web services...")
        
        web_results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_domain = {
                executor.submit(self._check_azure_web_services, result["domain"]): result["domain"] 
                for result in self.results
            }
            
            for future in tqdm(as_completed(future_to_domain), total=len(future_to_domain), desc="Web Checks"):
                domain = future_to_domain[future]
                try:
                    web_result = future.result()
                    if web_result["web_service"]:
                        web_results.append(web_result)
                except Exception as e:
                    logger.error(f"Error checking web service for {domain}: {str(e)}")
        
        # Merge web results with DNS results
        for web_result in web_results:
            for result in self.results:
                if result["domain"] == web_result["domain"]:
                    result.update({
                        "web_service": web_result["web_service"],
                        "status_code": web_result["status_code"],
                        "server": web_result["server"],
                        "web_title": web_result["title"]
                    })
        
        logger.info(f"Found {len(web_results)} active web services")
        
        # Save results if output is specified
        if self.output:
            self._save_results()
        
        return self.results
    
    def _save_results(self):
        """Save results to the specified output file"""
        file_extension = os.path.splitext(self.output)[1].lower()
        
        if file_extension == '.json':
            with open(self.output, 'w') as f:
                json.dump(self.results, f, indent=2)
        elif file_extension == '.csv':
            if not self.results:
                logger.warning("No results to save")
                return
            
            # Get all possible keys
            all_keys = set()
            for result in self.results:
                all_keys.update(result.keys())
            
            with open(self.output, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                writer.writeheader()
                writer.writerows(self.results)
        else:
            # Default to text format
            with open(self.output, 'w') as f:
                f.write(f"Azure DNS Enumeration Results\n")
                f.write(f"Domains checked: {len(self.domains)}\n")
                f.write(f"Subdomains checked: {len(self.subdomains)}\n")
                f.write(f"Total active domains found: {len(self.results)}\n\n")
                
                for result in self.results:
                    f.write(f"Domain: {result['domain']}\n")
                    if result.get("azure_service"):
                        f.write(f"Azure Service: {result['azure_service']}\n")
                    
                    if result.get("a_records"):
                        f.write(f"A Records: {', '.join(result['a_records'])}\n")
                    
                    if result.get("cname_records"):
                        f.write(f"CNAME Records: {', '.join(result['cname_records'])}\n")
                    
                    if result.get("web_service"):
                        f.write(f"Web Service: Yes (Status: {result.get('status_code')})\n")
                        if result.get("web_title"):
                            f.write(f"Web Title: {result.get('web_title')}\n")
                        if result.get("server"):
                            f.write(f"Server: {result.get('server')}\n")
                    
                    f.write("\n")
        
        logger.info(f"Results saved to {self.output}")
    
    def display_results(self):
        """Display results in a formatted text output"""
        print(f"\nAzure DNS Enumeration Results")
        print(f"Domains checked: {len(self.domains)}")
        print(f"Subdomains checked: {len(self.subdomains)}")
        print(f"Total active domains found: {len(self.results)}")
        
        for result in self.results:
            print(f"\nDomain: {result['domain']}")
            
            if result.get("azure_service"):
                print(f"Azure Service: {result['azure_service']}")
            
            if result.get("a_records"):
                print(f"A Records: {', '.join(result['a_records'])}")
            
            if result.get("cname_records"):
                print(f"CNAME Records: {', '.join(result['cname_records'])}")
            
            if result.get("web_service"):
                print(f"Web Service: Yes (Status: {result.get('status_code')})")
                if result.get("web_title"):
                    print(f"Web Title: {result.get('web_title')}")
                if result.get("server"):
                    print(f"Server: {result.get('server')}")


def main():
    # Disable insecure HTTPS warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        pass
    
    parser = argparse.ArgumentParser(description="Enumerate Azure DNS services using public information only")
    parser.add_argument("--domain", help="Specific Azure domain to scan (default: scan all common Azure domains)")
    parser.add_argument("--wordlist", help="Path to subdomain wordlist file")
    parser.add_argument("--output", help="Output file name (.json, .csv, or .txt)")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads (default: 10)")
    args = parser.parse_args()
    
    start_time = time.time()
    
    enumerator = AzureDnsEnumerator(
        domain=args.domain,
        wordlist=args.wordlist,
        output=args.output,
        threads=args.threads
    )
    
    results = enumerator.enumerate()
    
    if not args.output:
        enumerator.display_results()
    
    elapsed_time = time.time() - start_time
    logger.info(f"Enumeration completed in {elapsed_time:.2f} seconds")


if __name__ == "__main__":
    main()
