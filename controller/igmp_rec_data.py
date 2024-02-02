# Retrive Queue Data from UDP packet header

#!/usr/bin/env python3
import os
import sys

from scapy.all import (TCP,UDP, FieldLenField,FieldListField,IntField,IPOption,ShortField,get_if_list,
    sniff,hexdump,linehexdump,Raw)
from scapy.layers.inet import _IPOption_HDR
from scapy.all import *
import sys


def convert_to_int(list_val):
    return int("".join(list_val), 16)

if __name__ == '__main__':
    out_file = 'barlag.csv'
    rcvd_pkts = []
    rcvd_packets_loads = []

    sniff(filter='proto IGMP ',count=100000, iface="enp7s0", prn=lambda pkt: rcvd_packets_loads.append(linehexdump(pkt, dump=True, onlyhex=1)))
    with open(out_file, "w") as out:
        for pkt in rcvd_packets_loads:
            print("Packet = ",pkt)
            #out.write(pkt)
            tokens = pkt.split(" ")
            out.write("{},{},{},{}\n".format(convert_to_int(tokens[34:38]),convert_to_int(tokens[38:42]),convert_to_int(tokens[42:46]),convert_to_int(tokens[46:50])))
            #out.write("***************************************\n")
