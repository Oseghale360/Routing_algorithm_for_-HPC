#!/usr/bin/env python3
import sys

from scapy.all import (
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR


class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    #print("pkt.count = {}".format(pkt.count))
    name = "MRI"
    option = 31
    fields_desc = [_IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1))]
def handle_pkt(packet):
    print("Got the packet {} ".format(IPOption_MRI))
    packet.show2()
    print("True/False = {} ".format(IPOption_MRI in packet))
    out_file = 'parsed_data.csv'
    out = open(out_file, "w")
    if IPOption_MRI in packet:
        print("Packet options : ".format(packet.options))
        switch_traces = packet[IPOption_MRI].swtraces 
        for switch_trace in switch_traces:
            swid = switch_trace.swid
            qdepth = switch_trace.qdepth
            out.write("{},{}".format(swid, qdepth))
            print("Switch ID: {}, Queue Depth: {}".format(swid, qdepth))
    sys.stdout.flush()


def main():
    iface = 'enp7s0'
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(filter="igmp ", iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
