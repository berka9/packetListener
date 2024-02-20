import scapy.all as scapy
from scapy_http import http

def listen(interface):
    scapy.sniff(iface=interface, store=False,prn=analyze)

def analyze(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            print(packet[scapy.Raw].load)

listen("eth0")