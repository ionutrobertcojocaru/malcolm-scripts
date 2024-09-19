Scripts that I made to implement the following network analysis capabilities to [Malcolm](https://malcolm.fyi/), using its API:

1. OS Fingerprint
2. Services Scanner
3. Hosts Last Seen
4. Vulnerability Assessment

# OS Fingerprint
The script analyzes PCAP files and associates the most likely operating system using Satori software. The methods satori uses to perform OS fingerprint are documented here [satori](https://github.com/xnih/satori).

# Services Scanner
Scans for listening ports of each host that receive inbound traffic within the network.

# Vulnerability Assessment
The script pulls information from NetBox, builds the CPEs, and associates the relevant CVEs using the NIST API.

# How to install them
1. ```git clone https://github.com/xnih/satori```
2. Run Malcolm, and in Netbox create custom fields 'os' and 'last_seen' for each device.
3. Edit the code with your parameters.
4. Create cronjobs to run them regularly.
