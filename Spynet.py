#!/usr/bin/env python

import argparse
import scapy.all as scapy
import requests


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="{+} networkaddr + submask ( e.g. 192.168.1.0/24)")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a networkaddr with it's subnetmask. --help for more information")
    return options

def print_hosts(alive_hosts):
    for host in alive_hosts:
        print("[+] IP: " + host["ip"])

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for answer in answered_list:
        client_ip = {"ip": answer[1].psrc}
        client_list.append(client_ip)

    return client_list

#parse arguments passed by user
options = get_arguments()

#scan for alive hosts in the range
results = scan(options.target)

#print alive hosts in range
print_hosts(results)

#start portscan for each host alive and perform version and service scan

