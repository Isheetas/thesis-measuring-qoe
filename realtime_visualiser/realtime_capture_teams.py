from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet

 
import matplotlib.pyplot as plt

import asyncio
import websockets
import time
import json
import copy


import logging 
from datetime import datetime
import statistics

import pathlib
import os


HOST = "localhost"
PORT = 5001


pps_map = {}
pps_1 = 0
pps_2 = 0
pps_3 = 0

index = 1
start_time = 0

to_send = False
to_send_val = []





'''
-> self.flows => dictionary {'key=flowindex' : 'value=5tuple'}
-> self.data => dictionary {'key=flowindex' : 'value=[pps,loss,jitter]' }
-> mode: 1, or 0 (sniff packets or pcap read)
'''


class Handler():
    def __init__(self, srcIp):
        self.ws = None
        self.data = {}
        self.iface = 'WiFi'
        self.start = time.process_time()
        self.local = '192.168.0.180'
        self.srcIp = srcIp

        self.flows = {}
        self.flow_key = 0

        self. data_byte = '0x15'
        self.wind = 5
        self.state = {
            'audio': False,
            'video': False,
            'content': False,
        }

    


    async def connect(self):
        self.ws = await websockets.connect("ws://localhost:8000")   
        logging.getLogger('websockets.server').setLevel(logging.ERROR)
        logging.getLogger('websockets.protocol').setLevel(logging.ERROR)

      

    def start_sniff(self):
        
        filter = f'src host {self.srcIp} and dst host {self.local}'
        t = AsyncSniffer(filter=filter, prn=self.process_packet, iface=self.iface, store=False) 
        t.start()
        

    def get_flow(self, packet):


        srcip = ''
        dstip = ''
        srcport = 0
        dstport = 0
        protocol = ''

        if (TCP in packet):
            srcip = packet[IP].src
            dstip = packet[IP].dst
            protocol = 'TCP'

    
        if (UDP in packet):
            srcport = packet[UDP].sport
            dstport = packet[UDP].dport
            protocol = 'UDP'

        info = {
            'srcip': srcip,
            'srcport': srcport,
            'dstip': dstip,
            'dstport': dstport,
            'protocol': protocol
        }

        

        if (info not in self.flows.values()):
            self.flows[self.flow_key] = info
            loss = {
                'count': 0,
                'expectedSeq': 0,
                'total': 0,
            }
            len_obj = {
                'arr': [],
                'avg' : 0,
                'stddev' : 0,
            }

            media = {
                'media': '',
                'media_set' : '',
                'prev': '',
            }

            pps = {
                'count': 0,
                'pps_avg': 0,
                'pps_arr': [],
            }

            if (info['protocol'] == 'UDP'):
                self.data[self.flow_key] = {
                        'pps': pps, 
                        'jitter': {'prev_time': 0, 'all_delay': [], 'avg':0}, 
                        'loss': loss, 
                        'media':media,
                        'len': len_obj,
                        'active': False,
                    }           
            if (info['protocol'] == 'TCP'):
                self.data[self.flow_key] = {'pps': pps,'len': len_obj}

            self.state[dstport] = False
            self.flow_key += 1

        key = list(self.flows.keys())
        val = list(self.flows.values())
        pos = val.index(info)
        return key[pos]

    
    
    def process_packet(self, packet):
        #curr_time = time.process_time()
        #elapsed = curr_time - self.start

        flow_key = self.get_flow(packet) 

        if (packet.haslayer(UDP)):
            self.set_jitter(flow_key, packet)

        self.set_packet_len(flow_key, packet)
        self.set_pps(flow_key)
        #print(self.data[flow_info]['pps'])


    def set_pps(self, key):
        info = self.flows[key]
        
        self.data[key]['pps']['count'] += 1


    def set_packet_loss(self, key, packet):

        seq = self.get_seq(packet)
        loss = self.data[key]['loss']

        if (seq == loss['expectedSeq']):
            loss['expectedSeq'] += 1

        else:
            while (loss['expectedSeq'] != seq):
                loss['count'] += 1
                loss['expectedSeq'] += 1 


    def set_packet_len(self, key, packet):

        len_info = self.data[key]['len']
        len_info['arr'].append(packet.getlayer(IP).len)
        port = self.flows[key]['dstport']
        len_ = len(len_info['arr'])
        #print(f'{port}, {len_}')

    def get_seq(self,packet):
        seq = -1
        byte = packet.getlayer(Raw).load
        if (byte[0] == 5):
            val = byte[1:3]
            seq = int.from_bytes(val, "big")
        return seq

    def set_jitter(self, key, packet):

        jitter_data = self.data[key]['jitter']
        #print(jitter_data['prev_time'])
        if (jitter_data['prev_time'] == 0):
            jitter_data['prev_time'] = packet.time


        else:
            delay = int ((packet.time - jitter_data['prev_time']) * 1000)
            jitter_data['all_delay'].append(delay)
            #print(jitter_data['all_delay'])
            jitter_data['prev_time'] = packet.time
            if (len(jitter_data['all_delay']) > 2):
                stdev = statistics.stdev(jitter_data['all_delay'])
                #avg = sum(jitter_data['all_delay']) / len(jitter_data['all_delay'])
                jitter_data['avg'] = stdev
            #print(jitter_data['avg'])

    def detect_media(self, key, active_flows):
        print('active floes: ', active_flows)

        '''
        -> media , media_set => 100pc
        '''


        if (self.data[key]['media']['media_set'] != ''):
            return 'continue'

               
        p_len = self.data[key]['len']['avg']
        pps_avg = self.data[key]['pps']['avg']


        # flow is inactive
        if (pps_avg < 5):
            self.data[key]['active'] = False
            return 'inactive'
        self.data[key]['active'] = True


        if (p_len < 500 and active_flows < 3):
            if (self.data[key]['media']['prev'] == 'content or video'):
                self.data[key]['media']['media_set'] = 'video'
                self.state['audio'] = True
                return 'video'

            self.data[key]['media']['media_set'] = 'audio'
            self.state['audio'] = True
            
            return 'audio'

        if (p_len > 1000 and active_flows == 3):
            self.data[key]['media']['media_set'] = 'content'
            self.state['content'] = True
            return 'content'

        if (p_len > 700 and active_flows < 3 ):
            self.data[key]['media']['prev'] = 'content or video'
            return 'content or video'

        if (p_len < 700 and self.state['audio'] == True):
            self.data[key]['media']['media_set'] = 'video'
            self.state['video'] = True
            return 'video'

        
        # if (p_len > 1000 and pps > 70):
        # if a flow becomes active and a flow -> pps>10, pps <20, len>200
        # if all three flows are active:
        #
        return 'unknown' 
        


    def set_flows_active(self):

        count = 0

        for key in self.data:
            info = self.flows[key]
            if (info['protocol'] == 'TCP'):
                continue
            
            self.set_len_data(key)

            p_len = self.data[key]['len']['avg']

            # pps moving average 5 wind, pps info -> wrap in function
            pps_arr = self.data[key]['pps']['pps_arr']
            if (len(pps_arr) >= 5):
                pps_arr.pop(0)
            pps_arr.append(self.data[key]['pps']['count'])
            pps_arr = self.data[key]['pps']['pps_arr']
            pps_avg = sum(pps_arr)/len(pps_arr)
            self.data[key]['pps']['avg'] = pps_avg 

            if (pps_avg < 5):
                self.data[key]['active'] = False
                
            else:
                self.data[key]['active'] = True
                count += 1

        return count


    def set_state(self):


        active_flows = self.set_flows_active()

        # set if flow active or not
        # detect media (active_flows)

        for key in self.flows:
            info = self.flows[key]
            if (info['protocol'] == 'TCP'):
                continue
            
            media = self.detect_media(key, active_flows)
            if (media != 'continue'):
                self.data[key]['media']['media'] = media

        
        print(self.state)


    def set_len_data(self, key):
        len_info = self.data[key]['len']
        if (len(len_info['arr']) > 0):
            len_info['avg'] = sum(len_info['arr'])/len(len_info['arr'])
        #len_info['stddev'] = statistics.stdev(len_info['arr'])



    def construct_msg(self):

        to_send = {}

        self.set_state()
        data_fg = copy.deepcopy(self.data)
        for key in self.flows:

            #data_fg[key]['pps'] = data_fg[key]['pps'] * 2  #if speed is every 0.5sec
            info = self.flows[key]
            if (info['protocol'] == 'UDP'):
                if data_fg[key]['media']['media_set'] != '':
                    media = data_fg[key]['media']['media_set']
                else:
                    media = data_fg[key]['media']['media']
                to_send[key] = {
                    'info' : info,
                    'data' : {
                        'pps' : data_fg[key]['pps']['count'],
                        'jitter': data_fg[key]['jitter']['avg'],
                        'loss'  : data_fg[key]['loss']['count'],
                        'media' : media,
                        'len' : data_fg[key]['len']['avg']
                    }
                }

                self.data[key]['jitter']['all_delay'] = []
                self.data[key]['jitter']['avg'] = 0
                self.data[key]['loss']['count'] = 0
                self.data[key]['len']['arr'] = []


            if (info['protocol'] == 'TCP'):
                to_send[key] = {
                    'info' : info,
                    'data' : {
                        'pps' : data_fg[key]['pps']['count'],
                    }
                }
            
            logging.debug('Log: %s', {'time': str(datetime.time(datetime.now())), 'sent':to_send})


            self.data[key]['pps']['count'] = 0
            

        return json.dumps(to_send)

    


    async def start_sending(self):
        while True:
            #  handle tracking time here
           
            if (time.process_time() - self.start  >= 1):
                self.start = time.process_time()
                await self.ws.send(self.construct_msg())
            

                
            
                
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
    hdlr = Handler('52.243.65.49')
    await hdlr.connect()
    hdlr.start_sniff()
    await hdlr.start_sending()


if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

    

#sniff_packets('WiFi', '192.168.0.214')
