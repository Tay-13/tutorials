# #!/usr/bin/env python3

# from scapy.all import sniff, get_if_list, get_if_hwaddr
# from scapy.all import IP, TCP, Ether

import os
import sys

from scapy.all import TCP, FieldLenField, FieldListField, IntField, IPOption, ShortField, get_if_list, sniff, IP, Ether, get_if_hwaddr

from scapy.layers.inet import _IPOption_HDR

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


totals = {}
iface = get_if()


def handle_pkt(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        id_tup = (src_ip, dst_ip, proto, sport, dport)

        #filter packets that are sent from this interface. This is done to just focus on the receiving ones.
        #Some people had problems with this line since they set the src mac address to be the same than the destination, thus
        #all packets got filtered here.
        if get_if_hwaddr(iface) == pkt[Ether].src:
            return

        if id_tup not in totals:
            totals[id_tup] = 0
        totals[id_tup] += 1
        print("Received from %s total: %s" %
                (id_tup, totals[id_tup]))

def main():
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()



# import os
# import sys

# from scapy.all import (
#     TCP,
#     FieldLenField,
#     FieldListField,
#     IntField,
#     IPOption,
#     ShortField,
#     get_if_list,
#     sniff
# )
# from scapy.layers.inet import _IPOption_HDR


# def get_if():
#     ifs=get_if_list()
#     iface=None
#     for i in get_if_list():
#         if "eth0" in i:
#             iface=i
#             break;
#     if not iface:
#         print("Cannot find eth0 interface")
#         exit(1)
#     return iface

# class IPOption_MRI(IPOption):
#     name = "MRI"
#     option = 31
#     fields_desc = [ _IPOption_HDR,
#                     FieldLenField("length", None, fmt="B",
#                                   length_of="swids",
#                                   adjust=lambda pkt,l:l+4),
#                     ShortField("count", 0),
#                     FieldListField("swids",
#                                    [],
#                                    IntField("", 0),
#                                    length_from=lambda pkt:pkt.count*4) ]
# def handle_pkt(pkt):
#     if TCP in pkt and pkt[TCP].dport == 1234:
#         print("got a packet")
#         pkt.show2()
#     #    hexdump(pkt)
#         sys.stdout.flush()


# def main():
#     ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
#     iface = ifaces[0]
#     print("sniffing on %s" % iface)
#     sys.stdout.flush()
#     sniff(iface = iface,
#           prn = lambda x: handle_pkt(x))

# if __name__ == '__main__':
#     main()
