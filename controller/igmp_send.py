# Sends IGMP packets from the sender to receiver and gets the Queue Build up info on the switches. 

#!/usr/bin/env python3
import random
import socket
import sys
import time
from scapy.all import IP, UDP, TCP, Ether, get_if_hwaddr, get_if_list, sendp, sr1
import scapy.contrib.igmp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "enp7s0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:00:00:02')
    pkt = pkt /IP(dst=addr) / scapy.contrib.igmp.IGMP() / sys.argv[2]
    for i in range(1000000):
        #pkt.show2()
        sendp(pkt, iface=iface)
        time.sleep(0.005)


if __name__ == '__main__':
    main()
