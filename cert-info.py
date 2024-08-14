import csv
import ssl
import socket
from OpenSSL import crypto
from datetime import datetime
import dns.resolver
import requests


# Function to get WHOIS information of an IP address using IPAPI.co API
def get_ipapi_info(ip_address):
    try:
        url = f"https://ipapi.co/{ip_address}/json/"
        response = requests.get(url)
        data = response.json()

        # Store all relevant information provided by ipapi.co
        return {
            'ip': data.get('ip', 'N/A'),
            'city': data.get('city', 'N/A'),
            'region': data.get('region', 'N/A'),
            'region_code': data.get('region_code', 'N/A'),
            'country': data.get('country_name', 'N/A'),
            'country_code': data.get('country', 'N/A'),
            'continent_code': data.get('continent_code', 'N/A'),
            'in_eu': data.get('in_eu', 'N/A'),
            'postal': data.get('postal', 'N/A'),
            'latitude': data.get('latitude', 'N/A'),
            'longitude': data.get('longitude', 'N/A'),
            'timezone': data.get('timezone', 'N/A'),
            'utc_offset': data.get('utc_offset', 'N/A'),
            'country_calling_code': data.get('country_calling_code', 'N/A'),
            'currency': data.get('currency', 'N/A'),
            'languages': data.get('languages', 'N/A'),
            'asn': data.get('asn', 'N/A'),
            'org': data.get('org', 'N/A')
        }
    except Exception as e:
        return {
            'ip': ip_address,
            'city': 'Error',
            'region': 'Error',
            'region_code': 'Error',
            'country': 'Error',
            'country_code': 'Error',
            'continent_code': 'Error',
            'in_eu': 'Error',
            'postal': 'Error',
            'latitude': 'Error',
            'longitude': 'Error',
            'timezone': 'Error',
            'utc_offset': 'Error',
            'country_calling_code': 'Error',
            'currency': 'Error',
            'languages': 'Error',
            'asn': 'Error',
            'org': str(e)
        }

# Function to get SSL certificate information
def get_cert_info(domain, ip_address=None):
    try:
        # Use provided IP address or resolve the domain
        if not ip_address:
            ip_addresses = dns.resolver.resolve(domain, 'A')
            ip_address = ip_addresses[0].to_text()

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
                
                # Get IPAPI.co information of the IP address
                ipapi_info = get_ipapi_info(ip_address)
                
                return {
                    'domain': domain,
                    'common_name': common_name,
                    'san_names': ", ".join(san_names),
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'ip_addresses': ip_address,
                    'city': ipapi_info['city'],
                    'region': ipapi_info['region'],
                    'region_code': ipapi_info['region_code'],
                    'country': ipapi_info['country'],
                    'country_code': ipapi_info['country_code'],
                    'continent_code': ipapi_info['continent_code'],
                    'in_eu': ipapi_info['in_eu'],
                    'postal': ipapi_info['postal'],
                    'latitude': ipapi_info['latitude'],
                    'longitude': ipapi_info['longitude'],
                    'timezone': ipapi_info['timezone'],
                    'utc_offset': ipapi_info['utc_offset'],
                    'country_calling_code': ipapi_info['country_calling_code'],
                    'currency': ipapi_info['currency'],
                    'languages': ipapi_info['languages'],
                    'asn': ipapi_info['asn'],
                    'org': ipapi_info['org']
                }

    except Exception as e:
        return {
            'domain': domain,
            'common_name': 'Error',
            'san_names': 'Error',
            'expiry_date': 'Error',
            'ip_addresses': 'Error',
            'city': 'Error',
            'region': 'Error',
            'region_code': 'Error',
            'country': 'Error',
            'country_code': 'Error',
            'continent_code': 'Error',
            'in_eu': 'Error',
            'postal': 'Error',
            'latitude': 'Error',
            'longitude': 'Error',
            'timezone': 'Error',
            'utc_offset': 'Error',
            'country_calling_code': 'Error',
            'currency': 'Error',
            'languages': 'Error',
            'asn': 'Error',
            'org': 'Error'
        }

# Read the list of domains and optional IP addresses from the input CSV file
input_file = 'domains.csv'
output_file = 'certificate_info.csv'

with open(input_file, 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    domains = [row for row in reader]

# Collect the certificate information for each domain
cert_info_list = []
for entry in domains:
    domain = entry['domain']
    ip_address = entry.get('ip_address', None)
    cert_info = get_cert_info(domain, ip_address)
    cert_info_list.append(cert_info)

# Write the certificate information to the output CSV file
with open(output_file, 'w', newline='') as csvfile:
    fieldnames = [
        'domain', 
        'common_name', 
        'san_names', 
        'expiry_date', 
        'ip_addresses',
        'city', 
        'region', 
        'region_code', 
        'country', 
        'country_code', 
        'continent_code', 
        'in_eu', 
        'postal', 
        'latitude', 
        'longitude', 
        'timezone', 
        'utc_offset', 
        'country_calling_code', 
        'currency', 
        'languages', 
        'asn', 
        'org'
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    
    writer.writeheader()
    for cert_info in cert_info_list:
        writer.writerow(cert_info)

print(f"Certificate information has been written to {output_file}")
