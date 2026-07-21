"""
list_interfaces.py
-------------------
Prints the interface names scapy actually sees on this machine, in the
format main.py's --iface flag expects. Windows interface names are NOT
"wlan0"/"eth0" (that's Linux) — they're either a friendly name like
"Wi-Fi" or a GUID, depending on how Npcap exposes them.

Run: python3 list_interfaces.py
"""

from scapy.all import show_interfaces, conf

print("Interfaces scapy can see on this machine:\n")
show_interfaces()

print("\n---")
print("Copy the exact name from the 'Name' column above and use it like:")
print('    python main.py --iface "Wi-Fi"')
print("(quote it if it contains spaces)")
print(f"\nDefault interface scapy would pick if you don't specify one: {conf.iface}")
