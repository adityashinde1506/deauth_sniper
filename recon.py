from scapy.all import *
from libs.sniffer import Capture
from libs.traffic import Traffic
import logging

logging.basicConfig(level=logging.DEBUG,format="%(asctime)s-%(levelname)s: %(message)s")

class Recon:

    def __init__(self):
        self.capture=Capture()
        self.traffic=Traffic()
        logging.debug("Recon started.")

    def __run_capture(self,_time=30):
        logging.debug("Starting capture.")
        self.capture.start_capture(_time)
        self.capture.finish_capture()
        logging.debug("Finished capture.")

    def __pprint_SSIDs(self,SSIDs):
        for SSID in SSIDs:
            logging.info("Found SSID: %s MAC: %s"%SSID)

    def __pprint_devices(self,AP,devices):
        for device in devices:
            logging.info("Found device MAC: %s communicating with AP: %s"%(device,AP))

    def run_recon(self):
        self.__run_capture(60)
        beacons=self.capture.search("dot11_beacons")
        data=self.capture.search("dot11_data")
        SSIDs=self.traffic.get_SSIDs(beacons)
        for (ssid,addr) in SSIDs:
            devices=self.traffic.get_connected_devices(data,addr)
            self.__pprint_devices(addr,devices)
        self.__pprint_SSIDs(SSIDs)
        logging.debug("Recon Done.")

def main():
    recon=Recon()
    #addrs=recon.get_APs()
    recon.run_recon()

if __name__=="__main__":
    main()
