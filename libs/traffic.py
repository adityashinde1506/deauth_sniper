from scapy.all import *

class Traffic:

    def __init__(self):
        pass

    def get_traffic_hexdump(self,packets):
        for packet in packets:
            while packet.payload:
                packet=packet.payload
            print(hexdump(packet))

    def get_SSIDs(self,packets):
        APs=list()
        for packet in packets:
            SSID=None
            addr=None
            while packet:
                if type(packet)==type(Dot11()):
                    addr=packet.addr3
                elif type(packet)==type(Dot11Elt()):
                    if packet.ID==0:
                        SSID=packet.info
                if addr!=None and SSID!=None and (SSID,addr) not in APs:
                    APs.append((SSID,addr))
                packet=packet.payload
        return APs

    def get_connected_devices(self,packets,APmac):
        devices=list()
        for packet in packets:
            if packet.haslayer(Dot11):
                addrs=[packet.addr1,packet.addr2,packet.addr3,packet.addr4]
                if APmac in addrs:
                    for addr in addrs:
                        if addr not in devices and addr!=APmac and addr!="ff:ff:ff:ff:ff:ff":
                            devices.append(addr)
        return devices

def main():
    pass

if __name__=="__main__":
    main()
