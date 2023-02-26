#!usr/bin/env python
import scapy.all as scapy
from subprocess import call
from time import sleep
from mac_vendor_lookup import MacLookup


def scan(ip):
    arp_request = scapy.ARP(pdst = ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answered_list = scapy.srp(packet, verbose=False,  timeout = 1)[0]
    client = []
    for elements in answered_list:
        os = get_manufacturer(elements[1].hwsrc)
        client_dict = {"ip": elements[1].psrc, "mac": elements[1].hwsrc, "os": os}
        client.append(client_dict)
    return client

def get_manufacturer(mac):
    search_manufacturer = MacLookup()
    try:
        manufacture = search_manufacturer.lookup(mac)
    except:
        manufacture = "Unknown"
    return manufacture

def ready():
    print('''
         ▉▉▉▉    ▉▉  ▉▉▉▉▉▉▉▉▉▉  ▉▉▉▉▉▉▉▉▉▉   ip adress
         ▉▉ ▉▉   ▉▉  ▉▉              ▉▉                device info
         ▉▉  ▉▉  ▉▉  ▉▉▉▉▉▉▉▉▉▉      ▉▉         mac           wireless
         ▉▉   ▉▉ ▉▉  ▉▉              ▉▉               scan
    SCAN ▉▉    ▉▉▉▉  ▉▉▉▉▉▉▉▉▉▉      ▉▉    off3nied        network
    ''')

call(["clear"])
ready()
sleep(3)
call(["clear"])
try:
    while True:
        print("IP\t\t\tMAC adress\t\t\tOS")
        print("-----------------------------------------------------------------------------------")
        answer = scan("192.168.43.1/24")
        for elements in answer:
            print(elements["ip"] + "\t\t" + elements["mac"] + "\t\t" + elements["os"])
        sleep(1.500)
        call(["clear"])
except KeyboardInterrupt:
    print("\n[+] You disconnected from scanNET.Thanks you for using...")
