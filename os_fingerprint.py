import os
import subprocess
import requests
import json
from collections import Counter
import datetime

# Paths

# Define API credentials and base URL
username = 'root'
password = '12345678'
base_url = 'https://localhost/netbox/api/ipam/ip-addresses/'
pcaps_folder_path = '/pcap/processed'
satori_script_path = '/satori/satori.py'
satori_output_file = '/logs/satori_output-' + datetime.datetime.now().strftime('%Y-%m-%d-%H-%M') +'.txt'
os_guess_log = '/logs/fingerprints.txt'

# Define headers for JSON data
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}


def get_ips_to_determine_os():
    response = requests.get(base_url, auth=(username, password), headers=headers, verify=False)
    response.raise_for_status()
    return response.json()

def run_satori_on_pcaps(pcaps_folder_path, satori_script_path, satori_output_file):
    pcap_files = [os.path.join(pcaps_folder_path, f) for f in os.listdir(pcaps_folder_path) if f.endswith('.pcap')]
    with open(satori_output_file, 'a') as output_file:
        for pcap_file in pcap_files:
            subprocess.run(['python3', satori_script_path, '-r', pcap_file, '-m', 'tcp,dhcp,dns,ntp,ssh,http'], stdout=output_file)

def parse_satori_output(satori_output_file):
    os_dict = {}
    with open(satori_output_file, 'r') as file:
        for line in file:
            parts = line.split(';')
            if len(parts) < 4:
                continue
            ip = parts[1]
            method = parts[3]
            os_info = parts[-1]
            if (os_info != ' ' and os_info != '\n'):
                if ip not in os_dict:
                    os_dict[ip] = []
                if (method, os_info) not in os_dict[ip]:
                    os_dict[ip].append((method, os_info))
            else:
                continue
    return os_dict

def guess_os(evidence_list):
    os_counter = {}
    versions = {}
    for method, os_info in evidence_list:
        os_parts = os_info.split('|')
        for part in os_parts:
            os_name_version, confidence = part.rsplit(':', 1)
            os_name_version = os_name_version.strip()
            os_parts = os_name_version.split()
            os_name = os_parts[0]
            if len(os_parts) > 1:
                os_version = os_parts[1]
                if os_name not in versions and os_version != 'Device':
                    versions[os_name] = []
                    versions[os_name].append(os_version)
                elif os_name in versions and os_version != 'Device':
                    versions[os_name].append(os_version)
            os_counter[os_name] = os_counter.get(os_name, 0) + int(confidence.split('\n')[0])
    guessed_os = max(os_counter, key=os_counter.get)
    if len(versions[guessed_os]) == 0:
        guessed_ver = ''
    else:
        guessed_ver = max(versions[guessed_os], key=versions[guessed_os].count)

    if not os_counter:
        return 'Unknown', 'Unknown'
    
    return guessed_os, guessed_ver

# Function to update IP address
def update_ip_address(ip_id, os_value):
    url = f"{base_url}{ip_id}/"
    data = json.dumps({'custom_fields': {'os': os_value}})
    response = requests.patch(url, data=data, auth=(username, password), headers=headers, verify=False)
    response.raise_for_status()
    return response.json()


def main():
    # Step 1: Get IPs where OS is 'To determine'
    # Get the IP addresses
    ip_addresses = get_ips_to_determine_os()

    # Filter addresses with 'os' field as null
    null_os_addresses = [(ip['id'], ip['address'].split('/')[0]) for ip in ip_addresses['results'] if ip['custom_fields']['os'] is None]
    if len(null_os_addresses) == 0:
        return 0
    
    null_os_guesses = [ip[1] for ip in null_os_addresses]
    ip_id_dict = {ip[1]: ip[0] for ip in null_os_addresses}

    # Step 2: Run satori.py on all PCAP files
    run_satori_on_pcaps(pcaps_folder_path, satori_script_path, satori_output_file)
    

    # Step 3: Parse satori output file
    os_dict = parse_satori_output(satori_output_file)

    # Only keep entries that were in the original 'To determine' list
    filtered_os_dict = {ip: os_dict[ip] for ip in null_os_guesses if ip in os_dict}
    with open(os_guess_log, 'a') as file:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        file.write(f'Raw fingerprints of {timestamp}:\n')
        for ip, evidence_list in filtered_os_dict.items():
            file.write(f'{ip}: {evidence_list}\n')

    # Step 4: Guess OS based on the evidence
    os_guesses = {ip: guess_os(evidence_list) for ip, evidence_list in filtered_os_dict.items()}

    # Step 5: Update
   for ip, (guessed_os, guessed_ver) in os_guesses.items():
        os_value = f"{guessed_os} {guessed_ver}".strip()
        update_ip_address(ip_id_dict[ip], os_value)