from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

 
import matplotlib.pyplot as plt

import asyncio
import websockets
import time
import json
import copy
import numpy as np

import logging 
from datetime import datetime
import statistics

import pathlib
import os

from process_packet import ProcessPacket



class Handler():
    def __init__(self, srcIp):
        self.ws = None
        self.iface = 'WiFi'
        self.start = time.process_time()
        self.local = '192.168.0.180'
        self.srcIp = srcIp

        self.packet_handler = ProcessPacket()

    async def connect(self):
        self.ws = await websockets.connect("ws://localhost:8000")   
        logging.getLogger('websockets.server').setLevel(logging.ERROR)
        logging.getLogger('websockets.protocol').setLevel(logging.ERROR)

    def start_sniff(self):
        filter = f'src host {self.srcIp} and dst host {self.local}'
        t = AsyncSniffer(filter=filter, prn=self.process_packet, iface=self.iface, store=False) 
        t.start()
        
    def process_packet(self, packet):
        self.packet_handler.process_packet(packet)

    async def start_sending(self):
        while True:
            #  handle tracking time here
           
            if (time.process_time() - self.start  >= 1):
                self.start = time.process_time()
                msg = self.packet_handler.construct_msg()

                log = {
                    "time": str(datetime.time(datetime.now())),
                    "sent": msg,
                }
                logging.debug("Log: %s", json.dumps(log))

                await self.ws.send(json.dumps(msg))
            
async def main():
    #hdlr = Handler('192.168.0.214')

    filename = str(datetime.now())
    filename = filename.split('.')[0]
    filename = filename.replace('-', '_')
    filename = filename.replace(' ', '_')
    filename = filename.replace(':', '_')

    log_path = os.path.join(pathlib.Path().resolve(), 'logs', f'{filename}.log')



    logging.basicConfig(level=logging.DEBUG, filename=log_path)  #{str(datetime.now())}
    #hdlr = Handler('168.138.99.96')
    hdlr = Handler('144.195.23.124')
    await hdlr.connect()
    hdlr.start_sniff()
    await hdlr.start_sending()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

    

#sniff_packets('WiFi', '192.168.0.214')
