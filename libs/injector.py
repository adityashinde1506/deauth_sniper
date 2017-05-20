from scapy.all import *
import multiprocessing
import time

class Injector(multiprocessing.Process):

    def __init__(self):
        super().__init__()
        self.hwaddr=get_if_hwaddr("mon0")

    def prepare_packet(self,packet,is_acked=1):
        self.payload=packet
        self.WAIT_FOR_ACK=is_acked

    def run(self):
        if self.WAIT_FOR_ACK:
            ans=[]
            while len(ans)==0:
                ans=sr(self.payload,timeout=5,verbose=0)[0]
            print(ans[0][1].show())



class PacketFactory:

    true_src=get_if_hwaddr("mon0")
    fake_src=RandMAC()
    bcast="ff:ff:ff:ff:ff:ff"

    def prepare_Dot11ProbeReq(self):
        return Dot11(subtype=4,type=0,addr1=self.bcast,addr2=self.true_src,addr3=self.bcast,addr4=self.bcast)/Dot11ProbeReq()/Dot11Elt()/Dot11Elt()

    def prepare_Dot11Beacon(self):
        pass

def main():
    pf=PacketFactory()
    injector=Injector()
    dot11probe=pf.prepare_Dot11ProbeReq()
    injector.prepare_packet(dot11probe)
    injector.start()
    injector.join()


if __name__=="__main__":
    main()
