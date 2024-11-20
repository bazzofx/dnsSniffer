
import argparse
from scapy.all import arp
parser = argparse.ArgumentParser(description="DNS Sniffer")
parser.add_argument("--targetip", help="Target device you want to watch", required=True)
parser.add_argument("--iface", help="Interface to use for attack", required=True)
opts = parser.parse_args()


class Device:
    def __init(sefl):
        pass
    def mitm(self):
        pass
    def capture(self):
        pass
    def watch(self):
        pass


if __name__ == "__main__":
    device = Device()
    device.watch()
