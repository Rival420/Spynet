#!/usr/bin/env python

import argparse
import scapy.all as scapy
import socket
import sys
from datetime import datetime as dt
import os

Bold='\033[1m'
Red='\033[0;31m'
Green='\033[0;32m'
Blue='\033[0;94m'
Yellow='\033[0;93m'
Pink='\033[0;95m'
NC='\033[0m' # No Color

#globalvars
#start_port=1
#end_port=65535
#defaulttimeout=0.01

os.system("clear")

if (sys.version_info < (3, 0)):
	print("[-] Please, run it with Python3")
	sys.exit(0)

print(Bold + Green)
print("")
print("  /$$$$$$                                            /$$")
print(" /$$__  $$                                          | $$  ")
print("| $$  \__/  /$$$$$$  /$$   /$$ /$$$$$$$   /$$$$$$  /$$$$$$  ")
print("|  $$$$$$  /$$__  $$| $$  | $$| $$__  $$ /$$__  $$|_  $$_/  ")
print("\____  $$| $$  \ $$| $$  | $$| $$  \ $$| $$$$$$$$  | $$    ")
print("/$$  \ $$| $$  | $$| $$  | $$| $$  | $$| $$_____/  | $$ /$$")
print("|  $$$$$$/| $$$$$$$/|  $$$$$$$| $$  | $$|  $$$$$$$  |  $$$$/")
print(" \______/ | $$____/  \____  $$|__/  |__/ \_______/   \___/")
print("          | $$       /$$  | $$")
print("          | $$      |  $$$$$$/")
print("          |__/       \______/   ")
print("\n\t" + Red + "Made by: " + Bold + "Rival23 " + NC + Red + "and " + Bold + "Requird" + NC)
print("")
print(NC)

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--first-port", dest="start_port", help="first port for portscan", type=int)
    parser.add_argument("-l", "--last-port", dest="end_port", help="last port for portscan", type=int)
    parser.add_argument("-d", "--delay", dest="default_timeout", help="default delay for portscan is 0.01. the higher delay, the slower the scan.", type=float)
    parser.add_argument("-v", "--verbose", action="store_true", help="mainly for debugging")
    parser.add_argument("-o", "--output", action="store_true", help="save to log file")
    requiredNamed = parser.add_argument_group('required named arguments')
    requiredNamed.add_argument("-t", "--target", dest="target", help="networkaddr + submask ( e.g. 192.168.1.0/24)")
    options = parser.parse_args()
    #if not options.target:
    #    parser.error("[-] Please specify a networkaddr with it's subnetmask. --help for more information")
    if not options.start_port:
        #print("setting start port to 1")
        options.start_port = 1
    if not options.end_port:
        options.end_port = 1024
        #print("setting end port to " + str(options.end_port))
    if not options.default_timeout:
        #print("setting timeout to 0.01")
        options.default_timeout = 0.5

    return options

def show_argumets():
    print(Blue + Bold + "Target: " + NC + options.target)
    print(Blue + Bold + "First Port: " + NC + str(options.start_port))
    print(Blue + Bold + "Last Port: " + NC + str(options.end_port))
    print(Blue + Bold + "Delay: " + NC + str(options.default_timeout))
    if options.verbose:
        print(Blue + Bold + "Verbosity: " + NC + "On")
    if not options.verbose:
        print(Blue + Bold + "Verbosity: " + NC + "Off")
    if options.output:
        print(Blue + Bold + "Save log: " + NC + "On")
    if not options.output:
        print(Blue + Bold + "Save log: " + NC + "Off")
    print("")

def print_hosts(hosts):
    for host in hosts:
        print("[+] Host: " + host)

def print_ports(host, ports):
    print("[+] Host: " + host)
    for port in ports:
        print("\t[+] Open port: " + str(port))

def discover_host(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for answer in answered_list:
        client_ip = answer[1].psrc
        client_ip = str(client_ip)
        #print(client_ip)
        client_list.append(client_ip)

    return client_list

def getkey():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)

    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def discover_port(host):
    #gethostname
    target = socket.gethostbyname(host)
    ports = []
    for port in range(options.start_port, options.end_port):
        try:
            if options.verbose:
                print(Blue + str(port), end='\r')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(options.default_timeout)
            result = s.connect_ex((target, port))
            if result == 0:
                if options.verbose:
                    sys.stdout.write("\033[K")
                protocolname = 'tcp'
                service = socket.getservbyport(port, protocolname)
                print(Yellow + "\t[+] Open port: " + Bold + str(port) + "\t" + service + NC)
                if options.output:
                    logfile.write("\t[+] Open port: " + str(port) + "\t" + service + "\n")
                ports.append(result)
            s.close()
        except socket.error:
            print(Yellow + "\t[+] Open port: " + Bold + str(port) + "\tunknown" + NC)
            if options.output:
                logfile.write("\t[+] Open port: " + str(port) + "\tunknown" + "\n")
        except KeyboardInterrupt:
            action = input("\r" + Pink + "[!] Press " + Bold + "'s'" + NC + Pink + " to skip host or " + Bold + "'k'" + NC + Pink + " to finish the script: ")
            if (action == 's'):
                print(Blue + "[-] Skipping host: " + Bold + host + NC)
                if options.output:
                    logfile.write("[-] Skipping host: " + host + "\n")
                return 0
            elif (action == 'k'):
                print(Red + "[!] Exiting." + NC)
                print("")
                if options.output:
                    logfile.close()
                sys.exit(0)
            else:
                print(Red + "[!] Unrecognized option." + NC)
    return ports

def portscan_host(hosts):
    print("")
    for host in hosts:
        print(Green + "[+] Port scan started for host: " + Bold +  host + NC)
        if options.output:
            logfile.write("[+] Port scan started for host: " + host + "\n")
        ports = discover_port(host)
        #print_ports(host, ports)

#parse arguments passed by user
options = get_arguments()
show_argumets()
#open log file
if options.output:
    if not os.path.exists('logs'):
        os.makedirs('logs')
    if not os.path.exists('logs/' + options.target.replace('/', '_')):
        os.makedirs('logs/' + options.target.replace('/', '_'))
    logfile = open("logs/" + options.target.replace('/', '_') + '/' + dt.now().strftime("%d%m%Y_%H%M%S") + '.log', 'a')
#scan for alive hosts in the range
host_results = discover_host(options.target)
if options.verbose:
    print_hosts(host_results)
#start portscan for each host alive and perform version and service scan
portscan_host(host_results)
#close log file
if options.output:
    logfile.close()