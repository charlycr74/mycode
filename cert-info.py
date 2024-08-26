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

                # Extract certificate details excluding the certificate itself and private key
                cert_info = {
                    'domain': domain,
                    'common_name': x509.get_subject().CN,
                    'issuer': x509.get_issuer().CN,
                    'serial_number': x509.get_serial_number(),
                    'version': x509.get_version(),
                    'not_before': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S'),
                    'not_after': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ').strftime('%Y-%m-%d %H:%M:%S'),
                    'san_names': [],
                    'end_point': end_point,
                    'app_group': 'devops',
                    'app_name': 'cert_info'
                }

                # Get the SAN names as an array
                for i in range(x509.get_extension_count()):
                    ext = x509.get_extension(i)
                    if ext.get_short_name() == b'subjectAltName':
                        san_names = str(ext).replace("DNS:", "").split(", ")
                        cert_info['san_names'] = san_names
                        break

                return cert_info

    except Exception as e:
        return {
            'domain': domain,
            'common_name': 'Error',
            'issuer': 'Error',
            'serial_number': 'Error',
            'version': 'Error',
            'not_before': 'Error',
            'not_after': 'Error',
            'san_names': [],
            'end_point': end_point or 'Error',
            'app_group': 'devops',
            'app_name': 'cert_info'
        }

# Function to send data to Splunk
def send_to_splunk(splunk_url, splunk_token, data):
    # Prepare the event data for Splunk
    event_data = {
        'event': data
    }
    
    headers = {
        'Authorization': f'Splunk {splunk_token}',
        'Content-Type': 'application/json'
    }
    response = requests.post(splunk_url, headers=headers, data=json.dumps(event_data))
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
            'issuer',
            'serial_number',
            'version',
            'not_before',
            'not_after',
            'san_names', 
            'end_point'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for cert_info in cert_info_list:
            # Remove 'app_group' and 'app_name' before writing to CSV
            cert_info_for_csv = {k: cert_info[k] for k in fieldnames}

            # Convert san_names to a string for CSV output
            cert_info_for_csv['san_names'] = ", ".join(cert_info_for_csv['san_names'])
            
            writer.writerow(cert_info_for_csv)

    print(f"Certificate information has been written to {output_file} and sent to Splunk")

if __name__ == "__main__":
    main()
