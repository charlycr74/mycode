#pip install dnspython ipwhois pyOpenSSL

import csv
import ssl
import socket
from OpenSSL import crypto
from datetime import datetime
import dns.resolver
from ipwhois import IPWhois
import requests

# Function to perform DNS lookup and get IP addresses
def get_ip_addresses(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')
        return [ip.address for ip in result]
    except Exception as e:
        return [str(e)]

# Function to get WHOIS information of an IP address
def get_whois_info(ip_address):
    try:
        obj = IPWhois(ip_address)
        whois = obj.lookup_whois()
        return {
            'asn': whois.get('asn', 'N/A'),
            'asn_cidr': whois.get('asn_cidr', 'N/A'),
            'asn_country_code': whois.get('asn_country_code', 'N/A'),
            'asn_description': whois.get('asn_description', 'N/A')
        }
    except Exception as e:
        return {
            'asn': 'Error',
            'asn_cidr': 'Error',
            'asn_country_code': 'Error',
            'asn_description': str(e)
        }

# Function to get SSL certificate information
def get_cert_info(domain):
    try:
        # Perform DNS lookup to get IP addresses
        ip_addresses = get_ip_addresses(domain)
        
        # Set up a connection to the domain using the first IP address
        ip_address = ip_addresses[0]
        context = ssl.create_default_context()
        with socket.create_connection((ip_address, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                
                # Get the common name (CN)
                common_name = x509.get_subject().CN
                
                # Get the SAN names
                san_names = []
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_names = str(ext).replace("DNS:", "").split(", ")
                        break
                
                # Get the expiry date
                expiry_date = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
                
                # Get WHOIS information of the IP address
                whois_info = get_whois_info(ip_address)
                
                return {
                    'domain': domain,
                    'common_name': common_name,
                    'san_names': ", ".join(san_names),
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'ip_addresses': ", ".join(ip_addresses),
                    'asn': whois_info['asn'],
                    'asn_cidr': whois_info['asn_cidr'],
                    'asn_country_code': whois_info['asn_country_code'],
                    'asn_description': whois_info['asn_description']
                }
    
    except Exception as e:
        return {
            'domain': domain,
            'common_name': 'Error',
            'san_names': 'Error',
            'expiry_date': 'Error',
            'ip_addresses': 'Error',
            'asn': 'Error',
            'asn_cidr': 'Error',
            'asn_country_code': 'Error',
            'asn_description': str(e)
        }

# Read the list of domains from the input CSV file
input_file = 'domains.csv'
output_file = 'certificate_info.csv'

with open(input_file, 'r') as csvfile:
    reader = csv.reader(csvfile)
    domains = [row[0] for row in reader]

# Collect the certificate information for each domain
cert_info_list = []
for domain in domains:
    cert_info = get_cert_info(domain)
    cert_info_list.append(cert_info)

# Write the certificate information to the output CSV file
with open(output_file, 'w', newline='') as csvfile:
    fieldnames = [
        'domain', 
        'common_name', 
        'san_names', 
        'expiry_date', 
        'ip_addresses',
        'asn', 
        'asn_cidr', 
        'asn_country_code', 
        'asn_description'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for cert_info in cert_info_list:
        writer.writerow(cert_info)

print(f"Certificate information has been written to {output_file}")
