import json
import requests
import csv

# Configurazione dell'autenticazione e degli header
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}

username = 'x'
password = 'ciao'

# Funzione per eseguire una richiesta GET
def get_json(url):
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f"Failed to GET data from {url}: {response.status_code} - {response.text}")

# Funzione per leggere il file CSV
def read_csv(file_path):
    csv_data = {}
    with open(file_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ip = row['ip']
            protocol = row['protocol']
            port = int(row['port'])
            name = row['name']
            if ip not in csv_data:
                csv_data[ip] = {}
            if protocol not in csv_data[ip]:
                csv_data[ip][protocol] = {}
            csv_data[ip][protocol][port] = name
    return csv_data

# Ottieni i dati dalle API
netbox_api_ip = get_json('http://localhost/api/netbox/ipam/ip-addresses/')
netbox_api_services = get_json('http://localhost/api/netbox/ipam/services/')
destip_net = get_json('http://localhost/mapi/agg/destination.ip,network.transport,destination.port')

# Leggi il file CSV
csv_data = read_csv('/mnt/data/all.csv')

# Estrai gli IP dal file netbox_api_ip.json
ip_list = [entry['address'].split('/')[0] for entry in netbox_api_ip['results']]

# Crea un dizionario per mappare IP a porte e protocolli da netbox_api_services.json
ip_services = {}
for service in netbox_api_services['results']:
    for ip_entry in service['ipaddresses']:
        ip = ip_entry['address'].split('/')[0]
        protocol = service['protocol']['value']
        if ip not in ip_services:
            ip_services[ip] = {}
        if protocol not in ip_services[ip]:
            ip_services[ip][protocol] = set()
        for port in service['ports']:
            ip_services[ip][protocol].add(port)

# Aggiorna ip_services con i dati da destip-net.json
for bucket in destip_net['destination.ip']['buckets']:
    ip = bucket['key']
    if ip not in ip_services:
        ip_services[ip] = {}
    for transport in bucket['network.transport']['buckets']:
        protocol = transport['key']
        if protocol not in ip_services[ip]:
            ip_services[ip][protocol] = set()
        for port_bucket in transport['destination.port']['buckets']:
            port = port_bucket['key']
            ip_services[ip][protocol].add(port)

# Creare la lista delle modifiche necessarie
patch_data = []
for ip, protocols in ip_services.items():
    for protocol, ports in protocols.items():
        for port in ports:
            name = csv_data.get(ip, {}).get(protocol, {}).get(port, "")
            patch_data.append({
                "ip": ip,
                "protocol": protocol,
                "port": port,
                "name": name
            })

# Esegui la richiesta PATCH per ogni modifica
for data in patch_data:
    url = f"http://localhost/api/netbox/ipam/services/{data['ip']}/"
    patch_payload = {
        "protocol": data["protocol"],
        "port": data["port"],
        "name": data["name"]
    }
    response = requests.patch(url, headers=headers, json=patch_payload)
    if response.status_code == 200:
        print(f"Updated {data['ip']} with protocol {data['protocol']} on port {data['port']} and name {data['name']}")
    else:
        print(f"Failed to update {data['ip']}: {response.status_code} - {response.text}")
