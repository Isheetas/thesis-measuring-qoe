### PROCESS PCAP

from scapy.all import *
import numpy as np
import pdb
import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import statistics

from realtime_visualiser.process_packet import ProcessPacket


def process_pcap(file_name):
    print('Opening {}...'.format(file_name))
    packets = rdpcap(file_name)
  
    packet_in = []
    packet_out = []

    port_flow_map = {}
    key_num = 0

    packet_handler = ProcessPacket()

    start_time = 0


    plot_info = {}
    

    for i, pckt in enumerate(packets):
        if pckt.haslayer(UDP) and pckt.haslayer(IP):
            # catch different flows
            # catch the different direction
            # check the first byte of - 03/04/05 (wiregaurd) -> if 05 -> add the third byte (potentially the sequence) 
            udp_layer = pckt.getlayer(UDP)
            pckt_time = pckt.time


            if (udp_layer.sport == 8801):
                packet_handler.process_packet(pckt)
                
            if (pckt_time - start_time > 1):
                start_time = pckt_time
                data = packet_handler.construct_msg()

                update_data(data, plot_info)



    display_plot(plot_info)

def update_data(data_info, plot_info):
    for key in data_info:
        update_plot_info(key, plot_info)
        #if (plot_info[key]['info']['protocol'] == 'UDP'):
        data = data_info[key]['data']

        pps = data['pps']
        jit = data['jitter']
        mbps = data['mbps']
        loss = data['loss']
        media = data['media']

        plot_info[key]['pps'].append(pps)
        plot_info[key]['jitter'].append(jit)
        plot_info[key]['mbps'].append(mbps)
        plot_info[key]['loss'].append(loss)
        plot_info[key]['media'] = media


def update_plot_info(key, plot_info):
    if (key not in plot_info):
        #print('hekllo')
        plot_info[key] = {'pps': [], 'jitter': [], 'mbps': [], 'loss': [], 'media': ''}


def display_plot(plot_info):
    fig = make_subplots(rows=4, cols=1, subplot_titles=(['PPS',
                                                        'MBPS', 
                                                        'Loss', 
                                                        'Jitter']))
    i = 1
    for key in plot_info:
        key_data = plot_info[key]
        fig.add_trace(go.Scatter(y=key_data['pps'], name=f'{key_data["media"]}: pps'), row=i, col=1)
        fig.add_trace(go.Scatter(y=key_data['mbps'], name=f'{key_data["media"]}: mbps'), row=i, col=1)
        fig.add_trace(go.Scatter(y=key_data['loss'], name=f'{key_data["media"]}: loss'), row=i, col=1)
        i += 1

    fig.show()



    

    








if __name__ == "__main__":
    #process_pcap('Capture_analysis/cap1.pcapng')
    #process_pcap('../Capture_analysis/Base_pcap/cap5_pcap.pcap')
    #get_latency('Capture_analysis/audio_only.pcapng')
    #get_packet_loss('Capture_analysis/audio_only.pcapng')

    process_pcap('../captures/zoom/Experiments/0.5mbit.pcapng')

