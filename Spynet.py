#!/usr/bin/env python

import socket
import ipaddress
import argparse
import json
import netifaces
from typing import List
from scapy.all import ARP, Ether, srp
import asyncio

def get_local_network():
    default_gateway = netifaces.gateways()['default'][netifaces.AF_INET][0]
    for iface in netifaces.interfaces():
        iface_data = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in iface_data:
            for addr in iface_data[netifaces.AF_INET]:
                if addr['addr'] == default_gateway:
                    return f"{addr['addr']}/{addr['netmask']}"

def arp_scan(ip: str) -> bool:
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(arp_req, timeout=1, verbose=0)
    return len(ans) > 0

async def scan_port(ip: str, port: int) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
        writer.close()
        await writer.wait_closed()
        return True
    except asyncio.TimeoutError:
        return False
    except Exception as e:
        return False

async def scan_ports(ip: str, ports: List[int]) -> dict:
    open_ports = []
    tasks = [asyncio.create_task(scan_port(ip, port)) for port in ports]

    for i, task in enumerate(tasks):
        result = await task
        if result:
            open_ports.append(ports[i])

    return {"ip": ip, "ports": open_ports}

def save_json(filename: str, data: List[dict]) -> None:
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

async def main():
    parser = argparse.ArgumentParser(description='Home Network Scanner')
    parser.add_argument('-i', '--ip', default=get_local_network(), help="Target IP or IP range (e.g., '192.168.1.1', '192.168.1.1-192.168.1.5' or '192.168.1.0/24')")
    parser.add_argument('-p', '--port', default='1-10000', help="Target port or port range (e.g., '80', '80-100' or 'all')")
    parser.add_argument('-o', '--output', default='output.json', help="Output file for JSON results")
    args = parser.parse_args()

    target_ip = args.ip
    target_ports = args.port

    if "-" in target_ip:
        start_ip, end_ip = target_ip.split("-")
        ip_range = list(ipaddress.summarize_address_range(ipaddress.IPv4Address(start_ip.strip()), ipaddress.IPv4Address(end_ip.strip())))
    elif "/" in target_ip:
        ip_range = list(ipaddress.IPv4Network(target_ip, strict=False))
    else:
        ip_range = [ipaddress.IPv4Address(target_ip)]

    if target_ports.lower() == "all":
        ports_range = range(1, 65536)
    elif "-" in target_ports:
        start_port, end_port = target_ports.split("-")
        ports_range = range(int(start_port.strip()), int(end_port.strip()) + 1)
    else:
        ports_range = [int(target_ports)]

    live_hosts = []
    for ip in ip_range:
        if arp_scan(str(ip)):
            scan_result = await scan_ports(str(ip), ports_range)
	    live_hosts.append(scan_result)
            print(f"Host {ip} is alive with open ports: {scan_result['ports']}")

    save_json(args.output, live_hosts)
    print(f"Results saved in {args.output}")

if __name__ == "__main__":
    asyncio.run(main())
