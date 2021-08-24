from scapy.all import *
import statistics
from datetime import datetime
import logging 
import json

import numpy as np

class ProcessPacket:
    def __init__(self):
        self.data = {}
        self.flows = {}
        self.flow_key = 0
        self.state = {
            'audio': False,
            'video': False,
            'content': False,
        }

    def process_packet(self, packet):

        flow_key = self.get_flow(packet) 

        self.set_packet_len(flow_key, packet)
        self.set_pps(flow_key, packet)
        if (packet.haslayer(UDP)):
            self.set_jitter(flow_key, packet)

    def post_process(self):
        return

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
            srcip = packet[IP].src
            dstip = packet[IP].dst
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
                'std' : 0,
                'arr_5' : [],
                'max_len': 0,
                'avg_5': 0,
            }

            media = {
                'media': 'inactive',
                'state': '',
                'audio': 0,
                'video': 0,
                'content': 0,
                'unknown': 0,
            }

            pps = {
                'count': 0,
                'pps_avg': 0,
                'pps_arr': [],
                'std': 0,
                'max_pps': 0,
            }

            mbps = {
                'mbps_arr': [],
                'count': 0,
                'avg': 0,
            }



            if (info['protocol'] == 'UDP'):
                self.data[self.flow_key] = {
                        'pps': pps, 
                        'jitter': {'prev_time': 0, 'all_delay': [], 'avg':0}, 
                        'loss': loss, 
                        'media':media,
                        'len': len_obj,
                        'active': False,
                        'mbps': mbps,
                    }           
            if (info['protocol'] == 'TCP'):
                self.data[self.flow_key] = {'pps': pps,'len': len_obj, 'mbps': mbps,}

            self.state[dstport] = False
            self.flow_key += 1

        key = list(self.flows.keys())
        val = list(self.flows.values())
        pos = val.index(info)
        return key[pos]

    def set_pps(self, key, packet):
        info = self.flows[key]
        self.data[key]['pps']['count'] += 1
        self.data[key]['mbps']['count'] =  self.data[key]['mbps']['count'] + packet.getlayer(IP).len
        return
    
    def set_jitter(self, key, packet):
        jitter_data = self.data[key]['jitter']
        if (jitter_data['prev_time'] == 0):
            jitter_data['prev_time'] = packet.time
        else:
            delay = int ((packet.time - jitter_data['prev_time']) * 1000)
            jitter_data['all_delay'].append(delay)
            jitter_data['prev_time'] = packet.time
            if (len(jitter_data['all_delay']) > 2):
                stdev = statistics.stdev(jitter_data['all_delay'])
                jitter_data['avg'] = stdev

    def set_packet_loss(self, key, packet):
        seq = self.get_seq(packet)
        loss = self.data[key]['loss']

        if (seq == loss['expectedSeq']):
            loss['expectedSeq'] += 1

        else:
            while (loss['expectedSeq'] != seq):
                loss['count'] += 1
                loss['expectedSeq'] += 1 

    def get_seq(self, packet):
        seq = -1
        byte = packet.getlayer(Raw).load
        if (byte[0] == 5):
            val = byte[1:3]
            seq = int.from_bytes(val, "big")
        return seq

    def set_packet_len(self, key, packet):
        len_info = self.data[key]['len']
        len_info['arr'].append(packet.getlayer(IP).len)
        port = self.flows[key]['dstport']
        len_ = len(len_info['arr'])

        if (packet.getlayer(IP).len > len_info['max_len']):
            len_info['max_len'] = packet.getlayer(IP).len

    def set_packet_len_avg(self, key):
        len_info = self.data[key]['len']
        if (len(len_info['arr']) > 0):
            len_info['avg'] = sum(len_info['arr'])/len(len_info['arr'])

        arr_5 = len_info['arr_5']
        if (len(arr_5) >= 5):
            arr_5.pop(0)
        arr_5.append(len_info['avg'])
            
        len_info['avg_5'] = sum(arr_5)/len(arr_5)



    def set_pps_avg(self, key):
        pps_arr = self.data[key]['pps']['pps_arr']
        if (len(pps_arr) >= 5):
            pps_arr.pop(0)
        pps_arr.append(self.data[key]['pps']['count'])
        pps_arr = self.data[key]['pps']['pps_arr']
        pps_avg = sum(pps_arr)/len(pps_arr)
        self.data[key]['pps']['avg'] = pps_avg 
        self.data[key]['pps']['std'] = np.std(pps_arr)



        


##### MEDIA AND STATE DETECTION #####

    def set_state(self):
        # iterate through each flow
        active_flows = self.get_active_flows()

        # set if flow active or not
        # detect media (active_flows)

        for key in self.flows:
            info = self.flows[key]
            if (info['protocol'] == 'TCP'):
                continue
            
            #media = self.detect_media(key, active_flows)
            media_info = self.data[key]['media']
            pps = self.data[key]['pps']
            plen = self.data[key]['len']
            media, state = self._detect_media(plen['max_len'], pps['max_pps'], plen['avg_5'], pps['count'], plen['std'], pps['std'])
            if (state != 'inactive'):
                print(media_info)
                media_info[media] += 1
                media_info['media'] = self.calculate_media(media_info)

            media_info['state'] = state
            


    def calculate_media(self, media):
        max_media = ''
        max_count = 0
        if (media['audio'] > max_count):
            max_media = 'audio'
            max_count = media['audio']
        if (media['video'] > max_count):
            max_media = 'video'
            max_count = media['video']
        if (media['content'] > max_count):
            max_media = 'content'
            max_count = media['content']
        if (media['unknown'] > max_count):
            max_media = 'unknown'
            max_count = media['unknown']

        return max_media        

    def get_active_flows(self):
        count = 0
        for key in self.data:
            info = self.flows[key]
            if (info['protocol'] == 'TCP'):
                continue
            
            self.set_packet_len_avg(key)
            self.set_pps_avg(key)

            plen_avg = self.data[key]['len']['avg']
            #plen_avg = self.data[key]['len']['avg_5']
            pps_avg = self.data[key]['pps']['avg']

            if (pps_avg < 5):
                self.data[key]['active'] = False
                
            else:
                self.data[key]['active'] = True
                count += 1

        return count

    def detect_media(self, key, active_flows):
        


        len_info = self.data[key]['len']       
        plen_avg = self.data[key]['len']['avg_5']
        pps_avg = self.data[key]['pps']['avg']

        # flow is inactive
        if (pps_avg < 5):
            self.data[key]['active'] = False
            return 'inactive'
        
        self.data[key]['active'] = True


        # AUDIO
        if (plen_avg < 400 and active_flows < 3):
            self.data[key]['media']['media_set'] = 'audio'
            self.state['audio'] = True
            return 'audio'

        # VIDEO - change detected
        if (plen_avg < 700 and len_info['max_len'] > 900):
            self.data[key]['media']['media_set'] = 'video'
            self.state['video'] = True
            return 'video'

        # EITHER CONTENT or VIDEO
        if (plen_avg > 700 and active_flows < 3 ):
            self.data[key]['media']['prev'] = 'content or video'
            return 'content or video'


        #if (p_len < 700 and self.state['audio'] == True):
        #    self.data[key]['media']['media_set'] = 'video'
        #    self.state['video'] = True
        #    return 'video'

        # if (p_len > 1000 and pps > 70):
        # if a flow becomes active and a flow -> pps>10, pps <20, len>200
        # if all three flows are active:
        #
        return 'unknown' 


    def _detect_media(self, max_len, max_bps, curr_len, curr_bps, std_len, std_bps):


        if (max_len < 700 and curr_bps < 70 and curr_bps > 20):
            print(f'Audio: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}')

            return 'audio', 'active'


        if (max_len > 800 and curr_bps > 3 and curr_bps < 30 and std_bps< 10):
            print(f'Video min: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}')

            return 'video', 'video_minimised'
        
        if (max_len > 800 and std_bps < 50 and curr_bps > 3):
            print(f'Video max: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}')

            return 'video', 'video_maximised'

        if (max_len > 800 and std_bps > 10):
            print(f'content: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}')
            return 'content', 'content_active'

        if (curr_bps < 5 and curr_len > 120):
            print(f'Content: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}, curr_len: {curr_len}')
            return 'content', 'content_still'

        if (curr_bps < 5 and curr_len < 120):
            return  'unknown', 'inactive'

        print(f'UNKOWN: max_len: {max_len}, curr pps: {curr_bps}, std pps: {std_bps}, curr len: {curr_len}')

        return 'unknown', 'unknown'


            

##### MESSAGE FORMAT #####

    def construct_msg(self):

            to_send = {}

            self.set_state()
            data_fg = copy.deepcopy(self.data)
            for key in self.flows:

                #data_fg[key]['pps'] = data_fg[key]['pps'] * 2  #if speed is every 0.5sec
                info = self.flows[key]
                if (info['protocol'] == 'UDP'):
                    to_send[key] = {
                        'info' : info,
                        'data' : {
                            'pps' : data_fg[key]['pps']['count'],
                            'jitter': data_fg[key]['jitter']['avg'],
                            'loss'  : data_fg[key]['loss']['count'],
                            'media' : data_fg[key]['media']['media'],
                            'state' : data_fg[key]['media']['state'],
                            'len' : data_fg[key]['len']['avg'],
                            'mbps': (data_fg[key]['mbps']['count'])/1000,
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

                
                
                #logging.debug('Log: %s', log)


                self.data[key]['pps']['count'] = 0
                self.data[key]['mbps']['count'] = 0
                

            return to_send






    
    

