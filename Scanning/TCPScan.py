import sys
import logging

from scapy.layers.inet import TCP, IP

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

SYN = IP(dst="IP")/TCP(dport=80, flags="S")
print("Sends")
SYN.display()
print("response")
response = sr1(SYN, timeout=1, verbose=0)
response.display()
if int(response[TCP].flags) ==18:
    print("Sends")
    ACK = IP(dst="IP")/TCP(dport=80, flags="A", ack=(response[TCP].seq + 1))
    response2 = sr1(ACK, timeout=1, verbose=0)
    ACK.display()
    print("Response")
    response2.display()
else:
    print("Pas de SYN-ACK")