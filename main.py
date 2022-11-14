#!/usr/bin/python

import sys, getopt
from scapy.all import * #sniff,Ether,RandInt,RandMAC,srp1,sendp
from scapy.layers.l2 import Ether
from scapy.utils import mac2str

def main(argv):
    '''
    C:\\PycharmProjects\\NetSecLab>python ArpSpoofer.py –h
    usage: ArpSpoofer.py [-h] [-i IFACE] [-s SRC] [-d DELAY] [-gw]
            -t TARGET
    Spoof ARP tables
    optional arguments:
        -h, --help          show this help message and exit
        -i IFACE, --iface IFACE
                            Interface you wish to use
        -s SRC, --src SRC   The address you want for the attacker
        -d DELAY, --delay DELAY
                            Delay (in seconds) between messages
        -gw                 should GW be attacked as well
        -t TARGET, --target TARGET
                            IP of target
    '''
    print("ARP Spoofer")
    interface = "eth0"
    #src = get_if_addr(interface)
    delay=3
    attackGW=False
    target = "127.127.127.127"

    try:
        opts, args = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
    except getopt.GetoptError:
        print(main.__doc__)
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(main.__doc__)
            sys.exit()
        elif opt in ("-i", "--iface"):
            interface = arg
            #src = get_if_addr()
        elif opt in ("-s", "--src"):
            src = arg
        elif opt in ("-d", "--delay"):
            delay = arg
        elif opt in ("-gw", "--delay"):
            attackGW = True
        elif opt in ("-t", "--target"):
            target = arg







if __name__ == "__main__":
    main(sys.argv[1:])

'''# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main(sys.argv[1:])'''

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
