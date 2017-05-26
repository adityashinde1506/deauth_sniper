from scapy.all import *
from multiprocessing import Process,Queue,Event
import time
from traffic import Traffic

class Sniffer(Process):

    def __init__(self,queue,bground=0):
        super(Sniffer,self).__init__()
        self.timeout=20
        self.bground=bground
        self.out=queue
        self.FINISHED=Event()

    def set_timeout(self,_time):
        self.timeout=_time

    def print_packet(self,packet):
        print("=========================================")
        print(packet.payload.show())

    def __send_packets(self,packet):
        self.out.put(bytes(packet))

    def run(self):
        if self.bground:
            sniff(iface="mon0",prn=self.__send_packets)
        else:
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

    def __dot11_management(self,packet):
        if packet.haslayer(Dot11) and packet.getlayer(Dot11).type==0:
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


class LiveCapture(Capture):

    def __init__(self):
        Capture.__init__(self)
        self.sniffer=Sniffer(self.queue,1)

    def start_capture(self):
        self.sniffer.start()
        while 1:
            packet=RadioTap(self.queue.get())

def main():
    capture=LiveCapture()
    capture.start_capture()

if __name__=="__main__":
    main()
