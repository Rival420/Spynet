#!/usr/bin/env python

import argparse, socket, sys, os, difflib, shutil
try:
	import scapy.all as scapy
except ImportError:
	sys.exit("\033[0;31m\033[1mYou need scapy!\033[0m\033[0;31m You can instal it with '\033[0;31m\033[1msudo pip3 install scapy\033[0m\033[0;31m' or dowload it from '\033[0;31m\033[1mhttps://github.com/secdev/scapy\033[0m\033[0;31m'\033[0m")
from datetime import datetime as dt

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

if not os.name == 'nt':
	os.system("clear")
else:
	os.system("cls")

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
#print("\n\t" + Red + "Made by: " + Bold + "Rival23 " + NC + Red + "and " + Bold + "Requird" + NC)
print("")
print(NC)

def get_arguments():
	parser = argparse.ArgumentParser()
	parser.add_argument("-f", "--first-port", dest="start_port", help="first port for portscan", type=int)
	parser.add_argument("-l", "--last-port", dest="end_port", help="last port for portscan", type=int)
	parser.add_argument("-d", "--delay", dest="default_timeout", help="default delay for portscan is 0.01. the higher delay, the slower the scan.", type=float)
	parser.add_argument("-v", "--verbose", action="store_true", help="mainly for debugging")
	parser.add_argument("-o", "--output", action="store_true", help="save to log file")
	parser.add_argument("-c", "--check", action="store_true", help="check differences between scans")
	parser.add_argument("--clean", action="store_true", help="clean log files")
	requiredNamed = parser.add_argument_group('required named arguments')
	requiredNamed.add_argument("-t", "--target", dest="target", help="networkaddr ( e.g. 192.168.1.x) or networkaddr + submask ( e.g. 192.168.1.0/24)")
	options = parser.parse_args()
	if not options.target and not options.clean:
		parser.error("[-] Please specify a networkaddr or networkaddr with it's subnetmask. --help for more information\n")
	if not options.start_port:
		options.start_port = 1
	if not options.end_port:
		options.end_port = 1024
	if not options.default_timeout:
		options.default_timeout = 0.5
	if options.clean:
		print(Blue + Bold + "[!] Cleaning previous log files..." + NC)
		shutil.rmtree('tmp', ignore_errors=True)
		shutil.rmtree('logs', ignore_errors=True)
		print(Blue + Bold + "[!] Clean." + NC + '\n')
		if not options.target:
			sys.exit(0)

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
	if options.check:
		print(Blue + Bold + "Check scans: " + NC + "On")
	if not options.check:
		print(Blue + Bold + "Check scans: " + NC + "Off")

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
		client_list.append(client_ip)

	return client_list

def portscan_host(hosts):
	print("")
	#prepare log files
	if os.path.exists('tmp'):
		shutil.rmtree('tmp', ignore_errors=True)
	for host in hosts:
		if not os.path.exists('tmp'):
			os.makedirs('tmp')
		tmpfile = open("tmp/" + host + '.log', 'a')
		if options.output:
			logfile = open("logs/" + host + '/' + dt.now().strftime("%d%m%Y_%H%M%S") + '.log', 'a')
		print(Green + "[+] Port scan started for host: " + Bold +  host + NC)
		tmpfile.write("[+] Port scan started for host: " + host + "\n")
		if options.output:
			logfile.write("[+] Port scan started for host: " + host + "\n")
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
					tmpfile.write("\t[+] Open port: " + str(port) + "\t" + service + "\n")
					if options.output:
						logfile.write("\t[+] Open port: " + str(port) + "\t" + service + "\n")
					ports.append(result)
				s.close()
			except socket.error:
				print(Yellow + "\t[+] Open port: " + Bold + str(port) + "\tunknown" + NC)
				tmpfile.write("\t[+] Open port: " + str(port) + "\tunknown" + "\n")
				if options.output:
					logfile.write("\t[+] Open port: " + str(port) + "\tunknown" + "\n")
			except KeyboardInterrupt:
				action = input("\r" + Pink + "[!] Press " + Bold + "'s'" + NC + Pink + " to skip host or " + Bold + "'k'" + NC + Pink + " to finish the script: ")
				if (action == 's'):
					print(Blue + "[-] Skipping host: " + Bold + host + NC)
					tmpfile.write("[-] Skipping host: " + host + "\n")
					if options.output:
						logfile.write("[-] Skipping host: " + host + "\n")
					return 0
				elif (action == 'k'):
					print(Red + "[!] Exiting." + NC)
					print("")
					tmpfile.write("[!] Exiting.\n")
					if options.output:
						logfile.write("[!] Exiting.\n")
						logfile.close()
					sys.exit(0)
				else:
					print(Red + "[!] Unrecognized option." + NC)
		#close log file
		if options.output:
			logfile.close()

def check_scans(hosts):
	if not os.path.exists('logs'):
		print ("\t[!] There are no previous scans. Relaunch it adding the '-o' flag.\n")
		shutil.rmtree('tmp', ignore_errors=True)
		return (0)
	for host in hosts:
		tmppath = "tmp/"
		logs_path = "logs/" + host + '/'
		original_path = os.getcwd()

		if not os.path.exists(logs_path):
			print ("\n\t[!] There are no previous scans for " + host + ".\n")
		elif os.path.exists(logs_path):
			os.chdir(logs_path)
			files = sorted(os.listdir(os.getcwd()), key=os.path.getmtime)
			os.chdir(original_path)

			last_log = logs_path + files[-1]
			actual_log = os.path.join(tmppath, host + '.log')

			with open(actual_log, 'r') as file1:
				with open(last_log, 'r') as file2:
					diff = difflib.unified_diff(file1.readlines(), file2.readlines(), fromfile='file1', tofile='file2', lineterm='', n=0)
					lines = list(diff)[2:]
					title = [line[1:] for line in lines if line[0] == '+']
					added = [line[1:] for line in lines if line[0] == '+']
					removed = [line[1:] for line in lines if line[0] == '-']
					#if added or removed:
					print (Blue + Bold + "Checking differences for host " + host + ":" + NC)
					if added:
						print ('\n\t' + Red + Bold + 'Missing:' + NC)
						for line in added:
							print ('\t' + Red + Bold + line + NC)
					if removed:
						print ('\n\t' + Red + Bold + 'New' + NC)
						for line in removed:
							print ('\t' + Red + Bold + line + NC)
					if not added and not removed:
						print ("\n\t" + Green + Bold + "[!] There is nothing different." + NC + "\n")
	shutil.rmtree('tmp', ignore_errors=True)

def main(options):
    #parse arguments passed by user
	show_argumets()
	#scan for alive hosts in the range
	Start_Time = dt.now()
	host_results = discover_host(options.target)
	if options.verbose:
		print_hosts(host_results)
	#open log file
	if options.output:
		if not os.path.exists('logs'):
			os.makedirs('logs')
		for host in host_results:
			if not os.path.exists('logs/' + host):
				os.makedirs('logs/' + host)
	#start portscan for each host alive and perform version and service scan
	portscan_host(host_results)

	print(Blue)
	print("[*] The script took {0} seconds to scan".format(dt.now() - Start_Time))
	print(NC)

	#Check differences between scans
	if options.check:
		check_scans(host_results)

if __name__== "__main__":
	options = get_arguments()
	main(options)