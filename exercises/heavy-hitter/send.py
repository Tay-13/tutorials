#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import Ether, IP, sendp, get_if_hwaddr, get_if_list, TCP, Raw


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


# change here 
def send_random_traffic(dst_ip, num_packets):

    dst_addr = socket.gethostbyname(dst_ip)
    total_pkts = 0
    random_port = random.randint(1024,65000)
    iface = get_if()
    #For this exercise the destination mac address is not important. Just ignore the value we use.
    p = Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(iface)) / IP(dst=dst_addr)
    p = p / TCP(dport=random_port)
    for i in range(num_packets):
        sendp(p, iface = iface)
        total_pkts += 1
    print("Sent %s packets in total" % total_pkts)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python send.py <dst_ip> <num_packets>")
        sys.exit(1)
    else:
        dst_name = sys.argv[1]
        num_packets = int(sys.argv[2])
        send_random_traffic(dst_name, num_packets)

# def main():

#     if len(sys.argv)<3:
#         print('pass 2 arguments: <destination> "<message>"')
#         exit(1)

#     addr = socket.gethostbyname(sys.argv[1])
#     iface = get_if()

#     print("sending on interface %s to %s" % (iface, str(addr)))
#     pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
#     pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
#     pkt.show2()
#     sendp(pkt, iface=iface, verbose=False)


# if __name__ == '__main__':
#     main()
