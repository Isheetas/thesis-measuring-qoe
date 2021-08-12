from scapy.all import *
import matplotlib.pyplot as plt
import matplotlib.dates as matdates
import numpy as np
import pdb
import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots

import statistics


def process_pcap(file_name, audio, video, content):
    print('Opening {}...'.format(file_name))
    packets = rdpcap(file_name)
  
    packet_in = []
    packet_out = []

    port_flow_map = {}
    key_num = 0

    for i, pckt in enumerate(packets):
        if pckt.haslayer(UDP) and pckt.haslayer(IP):
            # catch different flows
            # catch the different direction
            # check the first byte of - 03/04/05 (wiregaurd) -> if 05 -> add the third byte (potentially the sequence) 
            udp_layer = pckt.getlayer(UDP)
            if (udp_layer.sport == 8801):
                if (udp_layer.dport in port_flow_map):
                    key = port_flow_map[udp_layer.dport]
                else:
                    port_flow_map[udp_layer.dport] = key_num
                    key = port_flow_map[udp_layer.dport]
                    packet_in.append([])
                    packet_out.append([])
                    key_num += 1
                    #print(port_flow_map)
            
                packet_list = packet_in[key]
                packet_list.append(pckt)

            if (udp_layer.dport == 8801):
                if (udp_layer.sport in port_flow_map):
                    key = port_flow_map[udp_layer.sport]
                else:
                    port_flow_map[udp_layer.sport] = key_num
                    key = port_flow_map[udp_layer.sport]
                    packet_out.append([])
                    packet_in.append([])
                    key_num += 1
                    #print(port_flow_map)

            
                packet_list = packet_out[key]
                packet_list.append(pckt)


    print(port_flow_map)

    # get sequence list

    return packet_in

def display_plot():

    state_1 = process_pcap(file_name='../Capture_analysis/Zoom/state_1.pcapng', audio=1000, video=1000, content=1000)
    state_6 = process_pcap(file_name='../Capture_analysis/Zoom/state_6.pcapng', audio=1000, video=1000, content=1000)
    state_7 = process_pcap(file_name='../Capture_analysis/Zoom/state_7.pcapng', audio=1000, video=1000, content=1000)
    state_9 = process_pcap(file_name='../Capture_analysis/Zoom/state_9.pcapng', audio=1000, video=1000, content=1000)



    fig = make_subplots(rows=2, cols=2, subplot_titles=(['All off',
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    fig_hist_bps = make_subplots(rows=2, cols=2, subplot_titles=(['All off', 
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    for i in range(3):
        ret = compute_kbps(state_1[i])
        fig.add_trace(go.Box(y=ret, name=f'State 1 Key {i}'), row=1, col=1)
        fig_hist_bps.add_trace(go.Histogram(x=ret, name=f'State 1 Key {i}'), row=1, col=1)

    for i in range(3):
        ret = compute_kbps(state_6[i])
        fig.add_trace(go.Box(y=ret, name=f'State 6 Key {i}'), row=2, col=1)
        fig_hist_bps.add_trace(go.Histogram(x=ret, name=f'State 6 Key {i}'), row=2, col=1)


    for i in range(3):
        ret = compute_kbps(state_7[i])
        fig.add_trace(go.Box(y=ret, name=f'State 7 Key {i}'), row=1, col=2)
        fig_hist_bps.add_trace(go.Histogram(x=ret, name=f'State 7 Key {i}'), row=1, col=2)

    for i in range(3):
        ret = compute_kbps(state_9[i])
        fig.add_trace(go.Box(y=ret, name=f'State 9 Key {i}'), row=2, col=2)
        fig_hist_bps.add_trace(go.Histogram(x=ret, name=f'State 9 Key {i}'), row=2, col=2)

    fig.update_layout(
        title_text="Kilobytes per second", 
    )
    fig.show()
    fig_hist_bps.update_layout(
        title_text="Kilobytes per second", 
        barmode='overlay'
    )

    fig_hist_bps.update_traces(opacity=0.50, xbins_size=500)
    fig_hist_bps.show()

    ############# PACKET LENGHT ####################

    fig_len = make_subplots(rows=2, cols=2, subplot_titles=(['All off', 
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    fig_hist_len = make_subplots(rows=2, cols=2, subplot_titles=(['All off', 
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    for i in range(3):
        ret = get_packet_len(state_1[i])
        fig_len.add_trace(go.Box(y=ret, name=f'State 1 Key {i}'), row=1, col=1)
        fig_hist_len.add_trace(go.Histogram(x=ret, name=f'State 1 Key {i}'), row=1, col=1)


    for i in range(3):
        ret = get_packet_len(state_6[i])
        fig_len.add_trace(go.Box(y=ret, name=f'State 6 Key {i}'), row=2, col=1)
        fig_hist_len.add_trace(go.Histogram(x=ret, name=f'State 6 Key {i}'), row=2, col=1)


    for i in range(3):
        ret = get_packet_len(state_7[i])
        fig_len.add_trace(go.Box(y=ret, name=f'State 7 Key {i}'), row=1, col=2)
        fig_hist_len.add_trace(go.Histogram(x=ret, name=f'State 7 Key {i}'), row=1, col=2)


    for i in range(3):
        ret = get_packet_len(state_9[i])
        fig_len.add_trace(go.Box(y=ret, name=f'State 9 Key {i}'), row=2, col=2)
        fig_hist_len.add_trace(go.Histogram(x=ret, name=f'State 9 Key {i}'), row=2, col=2)



    fig_len.update_layout(
        title_text="Packet length", 
    )
    fig_len.show()

    fig_hist_len.update_layout(
        title_text="Packet Length", 
        barmode='overlay'
    )
    fig_hist_len.update_traces(opacity=0.50, xbins_size=50)
    fig_hist_len.show()


    ################## Packet per second #######################

    fig_pps = make_subplots(rows=2, cols=2, subplot_titles=(['All off', 
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    fig_hist_pps = make_subplots(rows=2, cols=2, subplot_titles=(['All off', 
                                                        'Audio: on, Video: min, Content: off', 
                                                        'Audio: on, Video: max, Content: off', 
                                                        'Audio: on, Video: min, Content: on' ]))

    for i in range(3):
        ret = compute_pps(state_1[i])
        fig_pps.add_trace(go.Box(y=ret, name=f'State 1 Key {i}'), row=1, col=1)
        fig_hist_pps.add_trace(go.Histogram(x=ret, name=f'State 1 Key {i}'), row=1, col=1)


    for i in range(3):
        ret = compute_pps(state_6[i])
        fig_pps.add_trace(go.Box(y=ret, name=f'State 6 Key {i}'), row=2, col=1)
        fig_hist_pps.add_trace(go.Histogram(x=ret, name=f'State 6 Key {i}'), row=2, col=1)


    for i in range(3):
        ret = compute_pps(state_7[i])
        fig_pps.add_trace(go.Box(y=ret, name=f'State 7 Key {i}'), row=1, col=2)
        fig_hist_pps.add_trace(go.Histogram(x=ret, name=f'State 7 Key {i}'), row=1, col=2)


    for i in range(3):
        ret = compute_pps(state_9[i])
        fig_pps.add_trace(go.Box(y=ret, name=f'State 9 Key {i}'), row=2, col=2)
        fig_hist_pps.add_trace(go.Histogram(x=ret, name=f'State 9 Key {i}'), row=2, col=2)



    fig_pps.update_layout(
        title_text="Packet per second", 
    )
    fig_pps.show()

    fig_hist_pps.update_layout(
        title_text="Packet per second", 
        barmode='overlay'
    )
    fig_hist_pps.update_traces(opacity=0.50, xbins_size=5)
    fig_hist_pps.show()




    
    '''
    figure_sub = make_subplots(rows=2, cols=1, subplot_titles=['Packets length'])
    figure_sub.add_trace(go.Histogram(x=ret, name=f'Key {i}', legendgroup='1'), row=1, col=1)
    figure_sub.add_trace(go.Histogram(x=ret, name=f'Key {i}', legendgroup='2'), row=2, col=1)
    figure_sub.update_layout(
        height=800, 
        width=800, 
        title_text="Packet length", 
        xaxis2_title = 'Year',
        yaxis1_title = 'Age',
        yaxis2_title = 'Age',
        legend_tracegroupgap = 180,
    )

    figure_sub.show()
    figure_plen.show()

    '''

    print('finsihed')


def compute_packet_loss(packets):
    total_loss = 0
    lost_seq = []
    expected_sep = 0
    for pckt in packets:
        if (pckt_type_data(pckt)):

            seq = get_seq(pckt)
            #pdb.set_trace()

            if (seq in lost_seq):
                total_loss -= 1
                lost_seq.remove(seq)
                # remove from list
                continue

            if (expected_sep == 0):
                expected_sep = seq+1
            elif (expected_sep != seq):
                while (expected_sep != seq):
                    lost_seq.append(expected_sep)
                    total_loss +=1
                    expected_sep +=1
                expected_sep +=1
            elif(expected_sep == seq):
                expected_sep = seq+1

    print(lost_seq)
    
    return total_loss


def get_seq_list(packets):

    ret = []

    for pckt in packets:
        byte = pckt.getlayer(Raw).load
        if (byte[0] == 5):
            val = byte[1:3]
            val_int = int.from_bytes(val, "big")
            ret.append(val_int)
    
    return ret


def get_seq(pckt):
    val_int = -1
    byte = pckt.getlayer(Raw).load
    if (byte[0] == 5):
        val = byte[1:3]
        
        val_int = int.from_bytes(val, "big")

    return val_int

def pckt_type_data(pckt):
    byte = pckt.getlayer(Raw).load
    return (byte[0] == 5)



def compute_jitter(packets):

    ret = []
    prev_time = -1

    for pckt in packets:
        byte = pckt
        if (prev_time == -1):
            prev_time = pckt.time

        else:
            diff = pckt.time - prev_time
            prev_time = pckt.time
            ret.append(diff)
    
    stdev = statistics.stdev(ret)
    return stdev * 1000

def compute_pps(packets):
    
    ret = []

    #pdb.set_trace()

    if (len(packets) > 0):
        time = packets[0].time + 1
        pckt_cnt = 0

        for pckt in packets:
            if (pckt.time < time):
                pckt_cnt = pckt_cnt + 1
            else:
                ret.append(pckt_cnt)
                time = time + 1
                pckt_cnt = 0

    return ret

def compute_kbps(packets):
    ret = []

    #pdb.set_trace()

    if (len(packets) > 0):
        time = packets[0].time + 1
        pckt_cnt = 0

        for pckt in packets:
            if (pckt.time < time):
                pckt_cnt = pckt_cnt + pckt.getlayer(IP).len
            else:
                ret.append(pckt_cnt)
                time = time + 1
                pckt_cnt = 0

    return ret

def get_packet_len(packets):

    ret = []
    if (len(packets) > 0):
        for pckt in packets:
            ret.append(pckt.getlayer(IP).len)
    
    return ret






if __name__ == "__main__":
    #process_pcap('Capture_analysis/cap1.pcapng')
    #process_pcap('../Capture_analysis/Base_pcap/cap5_pcap.pcap')
    #get_latency('Capture_analysis/audio_only.pcapng')
    #get_packet_loss('Capture_analysis/audio_only.pcapng')

    display_plot()

