#!/usr/bin/env python3

import http.client, argparse, requests, socket, sys, os, difflib, shutil, http.client, csv, urllib
try:
	import scapy.all as scapy
except ImportError:
	sys.exit("\033[0;31m\033[1mYou need scapy!\033[0m\033[0;31m You can instal it with '\033[0;31m\033[1msudo pip3 install scapy\033[0m\033[0;31m' or dowload it from '\033[0;31m\033[1mhttps://github.com/secdev/scapy\033[0m\033[0;31m'\033[0m")
try:
	from git import Repo
except ImportError:
	sys.exit("\033[0;31m\033[1mYou need gitpython!\033[0m\033[0;31m You can instal it with '\033[0;31m\033[1msudo pip3 install gitpython\033[0m")
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
	parser.add_argument("-s", "--service", action="store_true", help="resolve service software")
	parser.add_argument("-sv", "--vuln", action="store_true", help="check if the service is vulnerable")
	parser.add_argument("--clean", action="store_true", help="clean log files")
	parser.add_argument("-a", "--add", dest="add", help="add new vulnerability: --add (-a is valid) \"service name, vuln name, link to exploit\" separated by \";\" withot space.")
	requiredNamed = parser.add_argument_group('required named arguments')
	requiredNamed.add_argument("-t", "--target", dest="target", help="networkhost ( e.g. 192.168.1.x) or networkhost + submask ( e.g. 192.168.1.0/24)")
	args = parser.parse_args()
	if not args.target and not args.clean and not args.add:
		parser.error("[-] Please specify a networkhost or networkhost with it's subnetmask. --help for more information\n")
	if not args.start_port:
		args.start_port = 1
	if not args.end_port:
		args.end_port = 1024
	if not args.default_timeout:
		args.default_timeout = 0.5
	if args.clean:
		print(Blue + Bold + "[!] Cleaning previous log files..." + NC)
		shutil.rmtree('tmp', ignore_errors=True)
		shutil.rmtree('logs', ignore_errors=True)
		print(Blue + Bold + "[!] Clean." + NC + '\n')
		if not args.target:
			sys.exit(0)
	if args.add and len(sys.argv) == 3:
		with open('vulndb/vulns.csv','a') as fd:
			fd.write(args.add.replace(";", "\t") + "\n")
		update_vulndb('upload')
		print(Green + Bold + "\nVulnerability added.\n" + NC)
		sys.exit(0)
	elif args.add and len(sys.argv) != 3:
		parser.error("[-] Please use --add (-a is valid) \"service name, vuln name, link to exploit\" separated by \";\" withot space.\n")
	return args

def show_arguments():
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
	if options.service:
		print(Blue + Bold + "Resolve service: " + NC + "On")
	if not options.service:
		print(Blue + Bold + "Resolve service: " + NC + "Off")
	if options.vuln:
		print(Blue + Bold + "Vuln check: " + NC + "On")
	if not options.vuln:
		print(Blue + Bold + "Vuln check: " + NC + "Off")

def check_input(host):
	action = input("\r" + Pink + "[!] Press " + Bold + "'s'" + NC + Pink + " to skip host or " + Bold + "'k'" + NC + Pink + " to finish the script: ")
	if action == 's':
		print(Blue + "[-] Skipping host: " + Bold + host + NC)
		write_log(host, "[-] Skipping host: " + host + "\n")
		return 1
	elif action == 'k':
		print(Red + "[!] Exiting." + NC)
		print("")
		write_log(host, "[!] Exiting.\n")
		shutil.rmtree('tmp', ignore_errors=True)
		sys.exit(0)
	else:
		print(Red + "[!] Unrecognized option." + NC)
		return 0

def print_hosts(hosts):
	for host in hosts:
		print("\t[+] Host: " + host)

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

	sorted_list = sorted(client_list, key=lambda ip: struct.unpack("!L", socket.inet_aton(ip))[0])

	return sorted_list

def get_banner(s, host, port):
	try:
		try:
			conn = http.client.HTTPConnection(host, port)
			conn.request("GET", "/")
			conn.getresponse()
			c = urllib.request.urlopen("http://"  + host + ":" + str(port))
			service = str(c.info()['Server'])
			return service
		except KeyboardInterrupt:
			return check_input(host)
		except:
			pass
		try:
			conn = http.client.HTTPSConnection(host, port)
			conn.request("GET", "/")
			conn.getresponse()
			c = urllib.request.urlopen("https://"  + host + ":" + str(port))
			service = str(c.info()['Server'])
			return service
		except KeyboardInterrupt:
			return check_input(host)
		except:
			pass
		try:
			socket.setdefaulttimeout(2)
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((host, port))
			service = str(s.recv(1024))
			return service
		except KeyboardInterrupt:
			return check_input(host)
		except:
			pass
	except KeyboardInterrupt:
		return check_input(host)
	return ""

def write_log(host, msg):
	tmpfile = open("tmp/" + host + '.log', 'a')
	if options.output:
		logfile = open("logs/" + host + '/' + actual_time + '.log', 'a')
	tmpfile.write(msg)
	if options.output:
		logfile.write(msg)

def print_table(data, cols, wide):
    '''Prints formatted data on columns of given width.'''
    n, r = divmod(len(data), cols)
    pat = '{{:{}}}'.format(wide)
    line = '\n'.join(pat * cols for _ in range(n))
    last_line = pat * r
    print(line.format(*data))
    print(last_line.format(*data[n*cols:]))

def portscan_host(hosts):
	print("")
	#prepare log files
	if os.path.exists('tmp'):
		shutil.rmtree('tmp', ignore_errors=True)
	for host in hosts:
		vulnerabilities = []
		host_results = []
		skip_host = 0
		vuln_index = 0
		if not os.path.exists('tmp'):
			os.makedirs('tmp')
		print(Green + "[+] Port scan started for host: " + Bold +  host + NC)
		write_log(host, "[+] Port scan started for host: " + host + "\n")
	#gethostname
		target = socket.gethostbyname(host)
		ports = []
		for port in range(options.start_port, options.end_port):
			isvulnerable = 0
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			if options.service:
				banner = get_banner(s, target, port)
				if banner == 1:
					break
			else:
				banner = ""
			if banner != "" and banner[1] == "'":
				banner = banner.replace("b'", "").replace("\\n'", "").replace("\\r", "").replace("Server ready.", "").replace("220 ", "").replace("_", " ")
				if options.vuln == 1:
					with open('vulndb/vulns.csv', newline = '') as vulns:
						vuln_reader = csv.reader(vulns, delimiter='\t')
						for vuln in vuln_reader:
							if vuln[0] in banner:
								vulnerabilities.append([])
								vulnerabilities[vuln_index].append(target)
								vulnerabilities[vuln_index].append(vuln[0])
								vulnerabilities[vuln_index].append(vuln[1])
								vulnerabilities[vuln_index].append(vuln[2])
								isvulnerable += 1
								vuln_index += 1
			try:
				if banner == "":
					banner = " "
				if options.verbose:
					print(Blue + "\t[i] Scaning port " + str(port), end='\r')
					if port == options.end_port - 1:
						sys.stdout.write("\033[K")
				socket.setdefaulttimeout(options.default_timeout)
				result = s.connect_ex((target, port))
				if result == 0:
					if options.verbose:
						sys.stdout.write("\033[K")
					protocolname = 'tcp'
					service = socket.getservbyport(port, protocolname)

					if options.vuln == 1 and options.service == 1:
						if isvulnerable > 0:
							vulnerable = Green + Bold + "Vulnerable" + NC
						else:
							vulnerable = Red + "Not vulnerable" + NC
					else:
						vulnerable = " "
					host_results.append([Yellow + "\t[+] Open port: " + str(port), service, banner, vulnerable])
					ports.append(result)
				s.close()
			except socket.error:
				host_results.append([Yellow + "\t[+] Open port: " + str(port), service, banner, vulnerable])
			except KeyboardInterrupt:
				skip_host = check_input(host)
			if skip_host == 1:
				break

		#Print host_results array
		s = [[str(e) for e in row] for row in host_results]
		lens = [max(map(len, col)) for col in zip(*s)]
		fmt = '\t'.join('{{:{}}}'.format(x) for x in lens)
		table = [fmt.format(*row) for row in s]
		print ('\n'.join(table))
		write_log(host, '\n'.join(table).replace(Yellow, "").replace(Green, "").replace(Red, "").replace(Bold, "").replace(NC, ""))

		last_host = ""
		for line in vulnerabilities:
			if last_host != line[0]:
				vuln_results = []
				print("")
				print(Green + "\t[!] Vulnerabilities for " + line[0] + NC)
				write_log(host, "\n\t[!] Vulnerabilities for " + line[0] + "\n")
				last_host = line[0]
				for row in vulnerabilities:
					vuln_results.append([Yellow + "\t\t[+] " + row[1], row[2], row[3] + NC])
				#Print vuln_results array
				s = [[str(e) for e in row] for row in vuln_results]
				lens = [max(map(len, col)) for col in zip(*s)]
				fmt = '\t'.join('{{:{}}}'.format(x) for x in lens)
				table = [fmt.format(*row) for row in s]
				print ('\n'.join(table))
				write_log(host, '\n'.join(table).replace(Yellow, "").replace(Bold, "").replace(NC, ""))

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

def update_vulndb(action):
	if action == 'update':
		if not os.path.exists('vulndb'):
			os.makedirs('vulndb')
			vulndb = 'vulndb/'
			Repo.clone_from('https://github.com/Rival420/VulnDB', vulndb, branch='master', depth=1)
		else:
			repo = Repo('vulndb/')
			origin = repo.remote('origin')
			origin.pull()
		print(Green + Bold + "\nDatabase updated.\n" + NC)

	if action == 'upload':
		if not os.path.exists('vulndb'):
			os.makedirs('vulndb')
			vulndb = 'vulndb/'
			Repo.clone_from('https://github.com/Rival420/VulnDB', vulndb, branch='master', depth=1)

			repo = Repo('vulndb/')
			repo.git.add(update=True)
			repo.index.commit('Added new vuln: ' + actual_time)
			origin = repo.remote(name='origin')
			origin.push()
		else:
			repo = Repo('vulndb/')
			repo.git.add(update=True)
			repo.index.commit('Added new vuln: ' + actual_time)
			origin = repo.remote(name='origin')
			origin.push()

def main(options):
	#Update vulndb
	ans = input('Would you like to update the vulnerabilities database? ').lower().strip()
	if ans in ['yes', 'y']:
		sys.stdout.write("\033[F")
		print("                                                          ")
		sys.stdout.write("\033[F")
		update_vulndb('update')
	if ans in ['no', 'n']:
		sys.stdout.write("\033[F")
		print("                                                          ")
		sys.stdout.write("\033[F")
    #parse arguments passed by user
	show_arguments()
	#scan for alive hosts in the range
	Start_Time = dt.now()
	host_results = discover_host(options.target)
	if options.verbose:
		print("\n[!] Host list:")
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

	shutil.rmtree('tmp', ignore_errors=True)

if __name__== "__main__":
	actual_time = dt.now().strftime("%d%m%Y_%H%M%S")
	options = get_arguments()
	main(options)