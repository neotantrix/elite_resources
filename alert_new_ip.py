
from scapy.all import sniff
from playsound import playsound
from time import time
from threading import Thread
from queue import Queue

ips = {}
mp3_to_sound = r'd:/downloads/treasure.mp3'

def handle_packet_blocking ( p ):
    now = time()
    key = p.payload.src
    
    if key in ips:
        v = ips[key]
        if v < (now - 90):
            del ips[key]
            
    if key not in ips:
        playsound(mp3_to_sound, block=False)
        
    ips[key] = now
    return None

packet_queue = Queue()

def print_updates_process ( ips ):
    now = time()
    keys = sorted(ips.keys(), key=lambda x: ips[x], reverse=True)
    for k in keys:
        print("%s updated %d seconds ago" % (k, round(now - ips[k])))

def process_loop ( ):
    while True:
        cmd, data = packet_queue.get()
        if cmd == 'print_updates':
            print_updates_process(ips)
        elif cmd == 'pkt':
            handle_packet_blocking(data)
        
        packet_queue.task_done()

def print_updates ( ):
    packet_queue.put(('print_updates', None))
        
def dosniff(nPackets=0):
   sniff(count=nPackets, filter="udp and dst port 5100", prn=lambda p: packet_queue.put(('pkt', p)))

def listen_for_new_cmdrs(noblock=True):
    process_loopt = Thread(target=process_loop)
    process_loopt.start()
    if noblock:
        sniff_thread = Thread(target=dosniff)
        sniff_thread.start()
    else:
        dosniff()
    
if __name__ == '__main__':
    listen_for_new_cmdrs(noblock=False)