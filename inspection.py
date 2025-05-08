#!/usr/bin/env python3
"""
Advanced URL OSINT Analyzer
- Checks HTTP headers
- Finds email addresses
- Discovers admin portals
- Performs WHOIS lookup
- Analyzes DNS records
"""

import requests
from urllib.parse import urlparse, urljoin
import whois
import re
from bs4 import BeautifulSoup
import dns.resolver
import argparse
import socket
from datetime import datetime

def get_headers(url):
    """Retrieve and analyze HTTP headers"""
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = dict(response.headers)
        
        print("\n[+] Header Information:")
        security_headers = {
            'X-Frame-Options': 'Clickjacking protection',
            'X-XSS-Protection': 'Cross-site scripting protection',
            'X-Content-Type-Options': 'MIME type sniffing protection',
            'Content-Security-Policy': 'Content security policy',
            'Strict-Transport-Security': 'HTTPS enforcement',
            'Server': 'Web server information'
        }
        
        for header, description in security_headers.items():
            if header in headers:
                print(f"  {header}: {headers[header]} ({description})")
            else:
                print(f"  {header}: Missing (Security risk)")
        
        return headers
    except Exception as e:
        print(f"  Header retrieval failed: {e}")
        return None

def find_emails(url):
    """Find email addresses on the webpage and related pages"""
    try:
        print("\n[+] Searching for email addresses...")
        response = requests.get(url, timeout=10)
        emails = set()
        
        # Find emails on main page
        email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails.update(re.findall(email_pattern, response.text))
        
        # Parse HTML to find links
        soup = BeautifulSoup(response.text, 'html.parser')
        links = [a.get('href') for a in soup.find_all('a', href=True)]
        
        # Check common contact pages
        contact_urls = ['contact', 'about', 'team', 'staff']
        for link in links:
            if any(contact in link.lower() for contact in contact_urls):
                try:
                    abs_link = urljoin(url, link)
                    contact_response = requests.get(abs_link, timeout=5)
                    emails.update(re.findall(email_pattern, contact_response.text))
                except:
                    continue
        
        if emails:
            print("  Found email addresses:")
            for email in sorted(emails):
                print(f"  - {email}")
        else:
            print("  No email addresses found")
            
        return emails
    except Exception as e:
        print(f"  Email search failed: {e}")
        return set()

def find_admin_portals(url):
    """Find common admin portal URLs"""
    print("\n[+] Searching for admin portals...")
    admin_paths = [
        'admin', 'login', 'wp-admin', 'dashboard',
        'manager', 'controlpanel', 'cpanel',
        'administrator', 'backend', 'admin.php'
    ]
    
    found = False
    for path in admin_paths:
        test_url = urljoin(url, path)
        try:
            response = requests.get(test_url, timeout=5)
            if response.status_code < 400:  # Check for successful or redirect responses
                print(f"  Found: {test_url} (Status: {response.status_code})")
                found = True
        except:
            continue
    
    if not found:
        print("  No common admin portals found")

def analyze_dns(domain):
    """Perform DNS lookups"""
    try:
        print("\n[+] DNS Information:")
        
        # A Records
        try:
            answers = dns.resolver.resolve(domain, 'A')
            print("  A Records:")
            for rdata in answers:
                print(f"    {rdata.address}")
        except dns.resolver.NoAnswer:
            pass
            
        # MX Records
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            print("  MX Records:")
            for mx in sorted(mx_records, key=lambda x: x.preference):
                print(f"    {mx.preference} {mx.exchange}")
        except dns.resolver.NoAnswer:
            pass
            
    except Exception as e:
        print(f"  DNS lookup failed: {e}")

def analyze_url(url):
    """Main analysis function"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    print(f"\n[+] Analyzing URL: {url}")
    
    # Basic URL parsing
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    
    print("\n[+] URL Components:")
    print(f"  Scheme: {parsed.scheme}")
    print(f"  Domain: {domain}")
    print(f"  Path: {parsed.path}")
    print(f"  Query: {parsed.query if parsed.query else 'None'}")
    
    # Security checks
    print("\n[+] Security Checks:")
    print(f"  Uses HTTPS: {'Yes' if parsed.scheme == 'https' else 'No'}")
    
    suspicious_keywords = ['login', 'auth', 'secure', 'account', 'verify']
    suspicious = any(kw in url.lower() for kw in suspicious_keywords)
    print(f"  Contains suspicious keywords: {'Yes' if suspicious else 'No'}")
    
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 'is.gd']
    is_shortened = any(s in domain for s in shorteners)
    print(f"  URL shortened: {'Yes' if is_shortened else 'No'}")
    
    # WHOIS lookup
    try:
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):  # Skip IP addresses
            print("\n[+] WHOIS Information:")
            w = whois.whois(domain)
            for key, value in w.items():
                if value and not isinstance(value, (list, dict)):
                    print(f"  {key}: {value}")
    except Exception as e:
        print(f"  WHOIS lookup failed: {e}")
    
    # Perform all checks
    get_headers(url)
    find_emails(url)
    find_admin_portals(url)
    analyze_dns(domain)

def main():
    parser = argparse.ArgumentParser(description='Advanced URL OSINT Analyzer')
    parser.add_argument('url', nargs='?', help='URL to analyze')
    args = parser.parse_args()
    
    if args.url:
        analyze_url(args.url)
    else:
        url = input("Enter URL to analyze: ").strip()
        if url:
            analyze_url(url)
        else:
            print("Error: No URL provided")

if __name__ == "__main__":
    main()