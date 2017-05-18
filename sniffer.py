from scapy.all import *


class Sniffer:

    def print_packet(self,packet):
        #print(dir(packet))
        print(packet.summary())

    def _sniff(self):
        sniff(iface="mon0",prn=self.print_packet,count=20)

def main():
    sniffer=Sniffer()
    sniffer._sniff()

main()
