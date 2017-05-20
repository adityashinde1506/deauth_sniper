from scapy.all import *
from multiprocessing import Process,Queue,Event
import time

class Sniffer(Process):

    def __init__(self,queue):
        super().__init__()
        self.timeout=20
        self.out=queue
        self.FINISHED=Event()

    def set_timeout(self,_time):
        self.timeout=_time

    def print_packet(self,packet):
        print("=========================================")
        print(packet.payload.show())

    def run(self):
        self.FINISHED.clear()
        capture=sniff(iface="mon0",timeout=self.timeout)
        self.out.put(list(map(bytes,capture)))
        self.FINISHED.set()



class Capture:

    def __init__(self):
        self.queue=Queue()
        self.sniffer=Sniffer(self.queue)
        self.packet_types={
            "all":lambda x: True,
            "dot11_beacons":self.__dot11_beacons,
            "dot11_data":self.__dot11_data
            }

    def __dot11_beacons(self,packet):
        if packet.haslayer(Dot11) and packet.getlayer(Dot11).type==0 and packet.getlayer(Dot11).subtype==8:
            return True
        else:
            return False

    def __dot11_data(self,packet):
        if packet.haslayer(Dot11) and packet.getlayer(Dot11).type==2:
            return True
        else:
            return False

    def start_capture(self,duration=20):
        self.sniffer.set_timeout(duration)
        self.sniffer.start()

    def finish_capture(self):
        self.sniffer.FINISHED.wait()
        self.packets=list(map(RadioTap,self.queue.get()))
        self.sniffer.join()

    def search(self,packet_type):
        return list(filter(self.packet_types[packet_type],self.packets))

def main():
    capture=Capture()
    capture.start_capture(50)
    capture.finish_capture()
    for packet in capture.search("all"):
        print(packet.summary())

if __name__=="__main__":
    main()
