import nmap
import re
import json
from datetime import datetime


def get_valid_network():
    while True:
        network = input("Enter Network (e.g., 192.168.0.0/24): ").strip()

        # Basic CIDR pattern check
        cidr_pattern = r"^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$"

        if not network:
            print("[!] Error: Network cannot be empty. Try again.")
            continue

        if not re.match(cidr_pattern, network):
            print("[!] Error: Invalid format. Use something like 192.168.0.0/24")
            continue

        # Validate each octet (0–255)
        ip, cidr = network.split("/")
        octets = ip.split(".")

        if any(int(o) < 0 or int(o) > 255 for o in octets):
            print("[!] Error: IP values must be between 0 and 255.")
            continue

        if not (0 <= int(cidr) <= 32):
            print("[!] Error: CIDR must be between /0 and /32.")
            continue

        return network


print("================================")
print("  NETWORK RECON & SCANNER 0.1  ")
print("================================")

# USER INPUT
network = get_valid_network()

print(f"\n[+] Starting scan on: {network}")
print("[+] Discovering live hosts...")

# SCANNER 1: HOST DISCOVERY
scanner = nmap.PortScanner()
scanned_network = scanner.scan(hosts=network, arguments="-sn")

hosts = list(scanned_network["scan"].keys())
print(f"[+] Total Live Hosts Found: {len(hosts)}")

# PREPARE JSON STRUCTURE
scan_results = {
    "network": network,
    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "live_hosts": []
}

# SCANNER 2: FAST PORT SCANNING
for each_host in hosts:
    print(f"\n[+] Live host: {each_host}")
    print(f"[+] Scanning ports on: {each_host}")

    port_scanner = nmap.PortScanner()

    port_scanner.scan(
        hosts=each_host,
        arguments="-sS -F --min-rate 500"
    )

    host_data = {
        "ip": each_host,
        "open_ports": []
    }

    print(f"[+] Open ports on {each_host}:")

    try:
        if "tcp" in port_scanner[each_host]:
            found = False

            for port, info in port_scanner[each_host]["tcp"].items():
                if info["state"] == "open":
                    print(f"   {port} → {info['name']}")

                    host_data["open_ports"].append({
                        "port": port,
                        "service": info["name"]
                    })

                    found = True

            if not found:
                print("   No open TCP ports found.")

        else:
            print("   No open TCP ports found.")

    except KeyError:
        print(f"   [!] Could not retrieve scan data for {each_host}")

    scan_results["live_hosts"].append(host_data)

# SAVE JSON OUTPUT
with open("scan_results.json", "w") as f:
    json.dump(scan_results, f, indent=4)

print("\n[+] Saved results to scan_results.json")

# SAVE READABLE REPORT
with open("scan_report.txt", "w") as f:
    f.write(f"Network: {network}\n")
    f.write(f"Scan Time: {scan_results['scan_time']}\n")
    f.write(f"Live Hosts: {len(hosts)}\n\n")

    for host in scan_results["live_hosts"]:
        f.write(f"Host: {host['ip']}\n")

        if host["open_ports"]:
            for p in host["open_ports"]:
                f.write(f"  - {p['port']} → {p['service']}\n")
        else:
            f.write("  No open TCP ports found\n")

        f.write("\n")

print("[+] Saved readable report to scan_report.txt")
print("\nScan completed successfully.")
