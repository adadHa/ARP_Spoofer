
from scapy.all import sniff ,ARP ,Ether,conf
import sys
import datetime
import arpUtil
intervals = [] # all the time we got is-at 
def intervalcalc(pack ): 
    intervals.append(pack.time )
    if len(intervals) > 1 : 
        print(f"""
            time : {datetime.datetime.now()}
            avg interval : { sum(map(lambda x,y : y-x , intervals[:-1],intervals[1::])) / (len(intervals)-1 )} , 
            last gap : {intervals[-1] - intervals[-2]} 
          """)
    else : 
        print(pack.time)
    
interface= sys.argv[1]
gatewaymac = arpUtil.getTargetMac(next(filter(lambda x : x[3] ==interface, dict(conf.route.__dict__)["routes"]))[2], interface)
print(gatewaymac)
sniff(
    lfilter = lambda x :  ARP in x and  x[Ether].src == gatewaymac and  x[ARP].op == 2 
      ,prn = intervalcalc) #sniff packets 