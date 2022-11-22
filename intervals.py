
from scapy.all import sniff ,ARP ,Ether
import sys
intervals = [] 
def intervalcalc(pack ): 
    intervals.append(pack.time )
    if len(intervals) > 1 : 
        print(f"""
            avg interval : { sum(map(lambda x,y : y-x , intervals[:-1],intervals[1::])) / (len(intervals)-1 )} , 
            last gap : {intervals[-1] - intervals[-2]} 
          """)
    else : 
        print(pack.time)
    


sniff(lfilter = lambda x :  ARP in x and  x[Ether].src == conf. ,prn = intervalcalc)