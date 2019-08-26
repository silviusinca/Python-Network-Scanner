#!/usr/bin/env python

import scapy.all as scapy
import argparse

def get_arguments():
  parser = argparse.ArgumentParser()
  parser.add_argument("-t", "--target", dest="ip_range", help="Specify the IP range you wish to scan")
  options = parser.parse_args()
  if not options.ip_range:
    parser.error("[-] Please specify an IP range, use --help for more info.")
  return options

def scan(ip):
  arp_request = scapy.ARP(pdst=ip)
  broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
  arp_req_broad = broadcast/arp_request
  answered_list = scapy.srp(arp_req_broad, timeout=1)[0]

  clients_list = []

  for el in answered_list:
    client_dict = {"ip": el[1].psrc, "mac": el[1].hwsrc}
    clients_list.append(client_dict)
  return clients_list

def print_result(results_list):
  print("IP\t\t\tMAC Address\n-------------------------------------------")
  for client in results_list:
    print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()

scan_result = scan(options.ip_range)
print_result(scan_result)
