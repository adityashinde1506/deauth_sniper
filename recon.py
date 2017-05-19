from scapy.all import *
from sniffer import Capture
import logging

logging.basicConfig(level=logging.DEBUG,format="%(asctime)s-%(levelname)s: %(message)s")

class Recon:

    def __init__(self):
        self.capture=Capture()
        logging.debug("Recon started.")

    def __run_capture(self,_time=30):
        logging.debug("Starting capture.")
        self.capture.start_capture(_time)
        self.capture.finish_capture()
        logging.debug("Finished capture.")


    def get_APs(self):
        self.__run_capture()
        packets=self.capture.search("dot11_beacons")
        AP_addrs=list(set(list(map(lambda x:x.getlayer(Dot11).addr3,packets))))
        logging.info("Found APs "+",".join(AP_addrs))
        

def main():
    recon=Recon()
    recon.get_APs()

if __name__=="__main__":
    main()
