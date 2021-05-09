#!/usr/bin/env python
import argparse
from scapy.all import Ether,ARP,arping,srp
# Use scapy.ls(scapy.OBJECT) to see all object attributes
# Use OBJECT.summary() or OBJECT.show() to see object/packet informatioon

def get_options():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest = "target", help = "IP or IP rangue (CIDR) to scan.")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info.")
    return options

def scan(ip):
    # Create ARP packet object instance
    # We set the IP that we are looking to in the request (pdst = ip)
    arp_request = ARP(pdst = ip)
    # Create an Ethernet frame
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    # Create combination of packets
    arp_request_broadcast = broadcast/arp_request
    # This will send the created packet before. Output [0][1] -> answered, unanswered
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # Create a client's dictionary with ips and mac addresses
    client_list = []
    for element in answered_list:
        client_dictionary = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dictionary)
    return client_list

def print_clients(client_list):
    print("IP\t\t\tMAC Address\n------------------------------------------------------")
    for client in client_list:
        print(client["ip"] + "\t\t" + client["mac"])
        
options = get_options()
print_clients(client_list = scan(options.target))