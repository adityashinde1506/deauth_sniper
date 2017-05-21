from scapy.all import *
import multiprocessing
import time

class Injector(multiprocessing.Process):

    def __init__(self):
        super().__init__()
        self.hwaddr=get_if_hwaddr("mon0")

    def prepare_packet(self,packet,is_acked=1,beacon=0):
        self.payload=packet
        self.WAIT_FOR_ACK=is_acked
        self.IS_BEACON=beacon

    def run(self):
        if self.WAIT_FOR_ACK:
            ans=srp1(self.payload,timeout=5,verbose=1,retry=10)
            print(ans)
        elif self.IS_BEACON:
            print(self.payload.show())
            send(self.payload,inter=2,loop=1)



class PacketFactory:

    true_src=get_if_hwaddr("mon0")
    fake_src=RandMAC()
    bcast="ff:ff:ff:ff:ff:ff"

    def prepare_Dot11ProbeReq(self):
        return Dot11(subtype=4,type=0,addr1=self.bcast,addr2=self.true_src,addr3=self.bcast,addr4=self.bcast)/Dot11ProbeReq()/Dot11Elt()/Dot11Elt()

    def prepare_Dot11Beacon(self):
        beacon=Dot11(type=0,subtype=8,addr1=self.bcast,addr2=self.true_src,addr3=self.true_src,addr4=None)/Dot11Beacon(cap="ESS+privacy")/Dot11Elt(ID="SSID",len=6,info="LOL_AP")
        radio=RadioTap()
        radio.payload=beacon
        return beacon

def main():
    pf=PacketFactory()
    injector=Injector()
    packet=pf.prepare_Dot11ProbeReq()
    print(bytes(packet))
    injector.prepare_packet(packet,is_acked=1,beacon=0)
    injector.start()
    time.sleep(100)
    injector.terminate()

if __name__=="__main__":
    main()
