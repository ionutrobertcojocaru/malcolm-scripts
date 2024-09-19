import requests
import json

# Function to create CPE for OS
def create_cpe_os(os_name):
    if os_name:
        return f"cpe:2.3:o:{os_name.lower()}"
    return None

# Function to create CPE for applications
def create_cpe_app(app_name, app_version):
    if app_name and app_version:
        return f"cpe:2.3:a:{app_name.lower()}:{app_version.lower()}"
    return None

# Function to create CPE for hardware
def create_cpe_hw(manufacturer):
    if manufacturer:
        return f"cpe:2.3:h:{manufacturer.lower()}"
    return None

# Function to get CVEs from NIST NVD
def get_cves(cpe):
    url = f"https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString={cpe}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        if 'result' in data and 'CVE_Items' in data['result']:
            return [item['cve']['CVE_data_meta']['ID'] for item in data['result']['CVE_Items']]
    return []

# Load the NetBox IP data
with open('/mnt/data/netbox_api_ip.json') as f:
    netbox_data = json.load(f)

# Load the application data
with open('/mnt/data/source.ip,zeek.software.unparsed_version.json') as f:
    app_data = json.load(f)

# Process NetBox data to get OS and hardware information
ip_data = []
for item in netbox_data['results']:
    ip_info = {}
    ip_info['ip'] = item['address']
    ip_info['os'] = item['custom_fields'].get('os')
    display = item['assigned_object']['device']['display']
    manufacturer = display.split('@')[0].strip()
    ip_info['manufacturer'] = manufacturer
    ip_data.append(ip_info)

# Process application data to get application information
app_info = []
for bucket in app_data['source.ip']['buckets']:
    ip = bucket['key']
    for version in bucket['zeek.software.unparsed_version']['buckets']:
        app_info.append({'ip': ip, 'app_name': 'application_name_placeholder', 'app_version': version['key']})

# Create CPEs and get CVEs
results = {}
for data in ip_data:
    cpe_os = create_cpe_os(data['os'])
    cpe_hw = create_cpe_hw(data['manufacturer'])
    cves_os = get_cves(cpe_os) if cpe_os else []
    cves_hw = get_cves(cpe_hw) if cpe_hw else []
    results[data['ip']] = {'os_cves': cves_os, 'hw_cves': cves_hw}

for app in app_info:
    cpe_app = create_cpe_app(app['app_name'], app['app_version'])
    cves_app = get_cves(cpe_app) if cpe_app else []
    if app['ip'] not in results:
        results[app['ip']] = {}
    results[app['ip']]['app_cves'] = cves_app

# Save the results to a file
output_file = 'vulnerability_assessment_output.txt'
with open(output_file, 'w') as f:
    for ip, cve_data in results.items():
        f.write(f"IP Address: {ip}\n")
        f.write(f"OS CVEs: {', '.join(cve_data.get('os_cves', []))}\n")
        f.write(f"Hardware CVEs: {', '.join(cve_data.get('hw_cves', []))}\n")
        f.write(f"Application CVEs: {', '.join(cve_data.get('app_cves', []))}\n")
        f.write("\n")

print(f"Vulnerability assessment completed. Results saved to {output_file}")
