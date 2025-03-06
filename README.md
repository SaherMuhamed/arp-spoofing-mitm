# ARP Spoofing Tool

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)  ![Kali](https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white)  ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)

A Python-based ARP spoofing tool designed to perform Man-in-the-Middle (MITM) attacks by spoofing ARP tables on a local network. This tool is intended for educational and ethical purposes only.

## Features

- **ARP Spoofing:** Spoof the ARP tables of a target device and the gateway to intercept traffic.
- **Stealth Mode:** Reduce detection likelihood by introducing randomized delays between spoofed packets.
- **Vendor Lookup:** Identify the vendor of the target and gateway devices using their MAC addresses.
- **Real-Time Packet Counter:** Track the number of spoofed packets sent in real-time.
- **Side-by-Side Output:** Display target and gateway information in a clean, side-by-side format.
- **Automatic ARP Table Restoration:** Restore ARP tables to their original state upon script termination.

## Prerequisites

- Python 3.x
- `scapy` library
- `colorama` library
- Root/Administrator privileges (for ARP spoofing and IP forwarding)

## Usage
1. Clone the repository:
    ```commandline
    git clone https://github.com/SaherMuhamed/arp-spoofing-mitm.git
    ```

2. Navigate to the project directory:
    ```commandline
    cd arp-spoofing-mitm
    ```
   
3. Install the required dependencies:
    ```commandline
    pip install scapy colorama
    ```

4. Run the script with the appropriate command-line options:
    ```commandline
    python3 arp_spoof.py -t <target_ip_address> -g <gateway_ip_address>
    ```
    Replace `<target_ip_address>` with the IP address of the target device and `<gateway_ip_address>` with the IP address of the gateway device.

5. To stop the script, press `Ctrl + C`. The ARP tables of the target and gateway devices will be restored to their original state.

## Command-Line Arguments

| Argument        | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| `-t`, `--target`  | Specify the IP address of the target device.                                |
| `-g`, `--gateway` | Specify the IP address of the gateway to spoof.                            |
| `-s`, `--stealth` | Enable stealth mode to reduce detection likelihood.                         |

## Screenshot
![](https://github.com/SaherMuhamed/arp-spoofing-mitm/blob/master/screenshots/Annotation_2025-03-07_012902.png)

## Disclaimer
This tool is intended for educational and testing purposes only. Unauthorized use of this tool on networks or devices without proper authorization is illegal. The developer is not responsible for any misuse or damage caused by this tool.


### Updates
`v1.0.1 - 28/12/2023`
- adding more verbosing output and vendor type
- improve spoofing functionality

`v2.1.0 - 07/03/2025`
- adding colors in outputs using `colorama` package
- displaying more useful information in output
- replacing fetch vendor with MAC address with `OUI lookup` json file instead of making requests usin `request` library, this will make the spoofing functionality faster and reliable 
