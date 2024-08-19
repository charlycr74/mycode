import csv
import ssl
import socket
from OpenSSL import crypto
from datetime import datetime
import dns.resolver
import sys
import requests
import json

# Function to get SSL certificate information
def get_cert_info(domain, end_point=None):
    try:
        # Use provided end_point or resolve the domain
        if not end_point:
            ip_addresses = dns.resolver.resolve(domain, 'A')
            end_point = ip_addresses[0].to_text()

        context = ssl.create_default_context()

        # Explicitly set the SNI hostname
        with socket.create_connection((end_point, 443)) as sock:
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

                return {
                    'domain': domain,
                    'common_name': common_name,
                    'san_names': ", ".join(san_names),
                    'expiry_date': expiry_date.strftime('%Y-%m-%d'),
                    'end_point': end_point,
                    'app_group': 'devops',
                    'app_name': 'cert_info'
                }

    except Exception as e:
        return {
            'domain': domain,
            'common_name': 'Error',
            'san_names': 'Error',
            'expiry_date': 'Error',
            'end_point': end_point or 'Error',
            'app_group': 'devops',
            'app_name': 'cert_info'
        }

# Function to send data to Splunk
def send_to_splunk(splunk_url, splunk_token, data):
    headers = {
        'Authorization': f'Splunk {splunk_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(splunk_url, headers=headers, data=json.dumps(data))
    return response.status_code, response.text

# Main function to run the script
def main():
    if len(sys.argv) != 5:
        print("Usage: python get_certificate_info.py <domains.csv> <output.csv> <splunk_url> <splunk_token>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    splunk_url = sys.argv[3]
    splunk_token = sys.argv[4]

    with open(input_file, 'r') as csvfile:
        reader = csv.DictReader(csvfile)
        domains = [row for row in reader if not row['domain'].startswith('#')]

    # Collect the certificate information for each domain
    cert_info_list = []
    for entry in domains:
        domain = entry['domain']
        end_point = entry.get('end_point', None)
        cert_info = get_cert_info(domain, end_point)
        cert_info_list.append(cert_info)

        # Send the certificate information to Splunk
        status_code, response_text = send_to_splunk(splunk_url, splunk_token, cert_info)
        if status_code != 200:
            print(f"Failed to send data to Splunk for domain {domain}. Response: {response_text}")

    # Write the certificate information to the output CSV file
    with open(output_file, 'w', newline='') as csvfile:
        fieldnames = [
            'domain', 
            'common_name', 
            'san_names', 
            'expiry_date', 
            'end_point',
            'app_group',
            'app_name'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for cert_info in cert_info_list:
            writer.writerow(cert_info)

    print(f"Certificate information has been written to {output_file} and sent to Splunk")

if __name__ == "__main__":
    main()
