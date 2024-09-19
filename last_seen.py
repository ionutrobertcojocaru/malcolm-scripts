import requests
import json

# Credentials and URLs
netbox_url = 'https://localhost/netbox/api/ipam/ip-addresses/'
mapi_url = 'https://localhost/mapi/agg/'
auth = ('root', '12345678')

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Perform the GET request to obtain Netbox data
netbox_response = requests.get(netbox_url, auth=auth, verify=False)
if netbox_response.status_code != 200:
    print(f"Failed to get Netbox data: {netbox_response.status_code} - {netbox_response.text}")
    exit()
netbox_data = netbox_response.json()

# Function to get MAPI data for a given IP address
def get_mapi_data(ip):
    mapi_params = {'filter': json.dumps({"source.ip": ip})}
    mapi_response = requests.get(mapi_url, params=mapi_params, auth=auth, verify=False)
    if mapi_response.status_code != 200:
        print(f"Failed to get MAPI data for IP {ip}: {mapi_response.status_code} - {mapi_response.text}")
        return None
    return mapi_response.json()

# Function to get the maximum last seen timestamp
def get_max_last_seen(netbox_last_seen, mapi_last_seen_range):
    netbox_last_seen = netbox_last_seen or None
    netbox_last_seen_ts = int(netbox_last_seen.split('T')[0].replace('-', ''))
    mapi_last_seen_ts = max(mapi_last_seen_range)
    return max(netbox_last_seen_ts, mapi_last_seen_ts)

# Extract IP addresses and their details from netbox_data
for ip_entry in netbox_data['results']:
    ip_address = ip_entry['address'].split('/')[0]
    netbox_last_seen = ip_entry['custom_fields'].get('last_seen')
    ip_id = ip_entry['id']
    
    # Get MAPI data for the current IP address
    mapi_data = get_mapi_data(ip_address)
    if mapi_data is None:
        continue
    
    # Extract corresponding mapi data
    for bucket in mapi_data['source.ip']['buckets']:
        if bucket['key'] == ip_address:
            mapi_last_seen_range = bucket['range']
            max_last_seen = get_max_last_seen(netbox_last_seen, mapi_last_seen_range)
            
            # Prepare the PATCH request payload
            payload = {
                "custom_fields": {
                    "last_seen": str(max_last_seen)
                }
            }
            
            # Perform the PATCH request
            patch_url = f"{netbox_url}{ip_id}/"
            response = requests.patch(patch_url, auth=auth, json=payload, verify=False)
            
            if response.status_code == 200:
                print(f"Successfully updated IP {ip_address} with last seen {max_last_seen}")
            else:
                print(f"Failed to update IP {ip_address}: {response.status_code} - {response.text}")

