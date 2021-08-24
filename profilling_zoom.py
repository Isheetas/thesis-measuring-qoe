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



pcap_config = {'thesis_meeting_cap' : {'zoom_addr': '168.138.99.71', 
                                        'local_port_1': 54747, 
                                        'local_port_2': 54749, 
                                        'local_port_3': 54750, 
                                        'local_addr' : '10.0.18.35',
                                        'time_offset': 1600000000
                                    },
                                        
                'all_in_one_4' : {'zoom_addr': '134.224.235.17', 
                                        'local_port_1': 60396, 
                                        'local_port_2': 60397, 
                                        'local_port_3': 60398, 
                                        'local_addr' : '192.168.0.180',
                                        'time_offset': 1621060000,
                                    },
                'cap3' : {'zoom_addr': '134.224.238.176', 
                                        'local_port_1': 59165, 
                                        'local_port_2': 59163, 
                                        'local_port_3': 59164, 
                                        'local_addr' : '192.168.0.180',
                                        'time_offset': 1616900000,
                                    },

                'cap1' : {'zoom_addr': '134.224.39.92', 
                                        'local_port_1': 57148, 
                                        'local_port_2': 62691, 
                                        'local_port_3': 57149, 
                                        'local_addr' : '192.168.0.180',
                                        'time_offset': 1616800000,
                                    }, 
                'cap4' : {'zoom_addr': '134.224.39.177', 
                                        'local_port_1': 55362, 
                                        'local_port_2': 55363, 
                                        'local_port_3': 61047, 
                                        'local_addr' : '192.168.0.180',
                                        'time_offset': 1622500000,
                                    }, 
                'cap5' : {'zoom_addr': '134.224.234.123', 
                                        'local_port_1': 64240, 
                                        'local_port_2': 64241, 
                                        'local_port_3': 64243, 
                                        'local_addr' : '10.248.94.177',
                                        'time_offset': 1623000000,
                                    },

                'cap6' : {'zoom_addr': '134.224.225.3', 
                                        'local_port_1': 63930, 
                                        'local_port_2': 63931, 
                                        'local_port_3': 63932, 
                                        'local_addr' : '10.100.113.110',
                                        'time_offset': 1623000000,
                                    },

                'cap7' : {'zoom_addr': '134.224.231.218', 
                                        'local_port_1': 60479, 
                                        'local_port_2': 60480, 
                                        'local_port_3': 60481, 
                                        'local_addr' : '10.100.113.110',
                                        'time_offset': 1623300000,
                                    },

                'cap8' : {'zoom_addr': '134.224.231.218', 
                                        'local_port_1': 60479, 
                                        'local_port_2': 60480, 
                                        'local_port_3': 60481, 
                                        'local_addr' : '10.100.113.110',
                                        'time_offset': 1623300000,
                                    },
                'base_cap2': {'zoom_addr': '144.195.41.203', 
                                        'local_port_1': 57377, 
                                        'local_port_2': 57378, 
                                        'local_port_3': 57379, 
                                        'local_addr' : '10.100.113.110',
                                        'time_offset': 1623300000,
                                    },
                '1Mbp_cap1': {'zoom_addr': '144.195.41.203', 
                                        'local_port_1': 57994, 
                                        'local_port_2': 57995, 
                                        'local_port_3': 57996, 
                                        'local_addr' : '10.100.113.110',
                                        'time_offset': 1623300000,
                                    },

                }

def process_pcap(file_name, pcap_key):
    print('Opening {}...'.format(file_name))
    packets = rdpcap(file_name)
    
    local_addr = pcap_config.get(pcap_key).get('local_addr')
    local_port_1 = pcap_config.get(pcap_key).get('local_port_1')        
    local_port_2 = pcap_config.get(pcap_key).get('local_port_2')        
    local_port_3 = pcap_config.get(pcap_key).get('local_port_3')        

    zoom_addr = pcap_config.get(pcap_key).get('zoom_addr')
    zoom_port_1 = 8801

    time_offset = pcap_config.get(pcap_key).get('time_offset')


    packet_1_out = []
    packet_2_out = []
    packet_3_out = []

    packet_1_in = []
    packet_2_in = []
    packet_3_in = []

    tcp_packet_in = []
    tcp_packet_out= []

    for i, pckt in enumerate(packets):
        if pckt.haslayer(UDP) and pckt.haslayer(IP):
            # catch different flows
            # catch the different direction
            # check the first byte of - 03/04/05 (wiregaurd) -> if 05 -> add the third byte (potentially the sequence) 

            ip_layer = pckt.getlayer(IP)
            udp_layer = pckt.getlayer(UDP)
            if (ip_layer.dst == zoom_addr):
                if (udp_layer.sport == local_port_1):
                    if (pckt_type_data(pckt)):
                        packet_1_out.append(pckt)

                if (udp_layer.sport == local_port_2):
                    if (pckt_type_data(pckt)):
                        packet_2_out.append(pckt)

                if (udp_layer.sport == local_port_3):
                    if (pckt_type_data(pckt)):
                        packet_3_out.append(pckt)

            if (ip_layer.src == zoom_addr):
                if (udp_layer.dport == local_port_1):
                    if (pckt_type_data(pckt)):
                        packet_1_in.append(pckt)
                
                if (udp_layer.dport == local_port_2):
                    if (pckt_type_data(pckt)):
                        packet_2_in.append(pckt)

                if (udp_layer.dport == local_port_3):
                    if (pckt_type_data(pckt)):
                        packet_3_in.append(pckt)

        if pckt.haslayer(TCP) and pckt.haslayer(IP):
            ip_layer = pckt.getlayer(IP)
            tcp_layer = pckt.getlayer(TCP)

            if (ip_layer.dst == zoom_addr):
                tcp_packet_out.append(pckt)

            if (ip_layer.src == zoom_addr):
                tcp_packet_in.append(pckt)

    
   

    fig = make_subplots(rows=2, cols=3, subplot_titles=(f'Outgoing Interpacket variation - {local_addr} -> {zoom_addr}', f'Outgoing Packets Per Second {pcap_key}', 'Outgoing Bytes Per Second', 
                                                        f'Incoming Interpacket variation - {zoom_addr} -> {local_addr}', 'Incoming Packets Per Second', 'Incoming Bytes Per Second'))

    ## Outgoing 
    # interpacket variartion 
    del_1, x_21 = get_inter_pckt_variation(packet_1_out)
    del_2, x_22 = get_inter_pckt_variation(packet_2_out)
    del_3, x_23 = get_inter_pckt_variation(packet_3_out)

    fig.add_trace(go.Scatter(x=x_21, y=del_1, mode='lines', name=f'udp {local_port_1}'), row=1, col=1)
    fig.add_trace(go.Scatter(x=x_22, y=del_2, mode='lines', name=f'udp {local_port_2}'), row=1, col=1)
    fig.add_trace(go.Scatter(x=x_23, y=del_3, mode='lines', name=f'udp {local_port_3}'), row=1, col=1)

    # packets per second
    pps_1 = packets_ps(packet_1_out)
    pps_2 = packets_ps(packet_2_out)
    pps_3 = packets_ps(packet_3_out)
    pps_tcp = packets_ps(tcp_packet_out)

    fig.add_trace(go.Scatter(y=pps_1, mode='lines', name=f'udp {local_port_1}'), row=1, col=2)
    fig.add_trace(go.Scatter(y=pps_2, mode='lines', name=f'udp {local_port_2}'), row=1, col=2)
    fig.add_trace(go.Scatter(y=pps_3, mode='lines', name=f'udp {local_port_3}'), row=1, col=2)
    fig.add_trace(go.Scatter(y=pps_tcp, mode='lines', name=f'tcp port'), row=1, col=2)

    # bytes per second
    pps_1 = bytes_ps(packet_1_out)
    pps_2 = bytes_ps(packet_2_out)
    pps_3 = bytes_ps(packet_3_out)
    pps_tcp = bytes_ps(tcp_packet_out)

    fig.add_trace(go.Scatter(y=pps_1, mode='lines', name=f'udp {local_port_1}'), row=1, col=3)
    fig.add_trace(go.Scatter(y=pps_2, mode='lines', name=f'udp {local_port_2}'), row=1, col=3)
    fig.add_trace(go.Scatter(y=pps_3, mode='lines', name=f'udp {local_port_3}'), row=1, col=3)
    fig.add_trace(go.Scatter(y=pps_tcp, mode='lines', name=f'tcp port'), row=1, col=3)

    ## Incoming
    # Interpacket variation 
    del_1, x_1 = get_inter_pckt_variation(packet_1_in)
    del_2, x_2 = get_inter_pckt_variation(packet_2_in)
    del_3, x_3 = get_inter_pckt_variation(packet_3_in)

    fig.add_trace(go.Scatter(x=x_2, y=del_1, mode='lines', name=f'udp {local_port_1}'), row=2, col=1)
    fig.add_trace(go.Scatter(x=x_2, y=del_2, mode='lines', name=f'udp {local_port_2}'), row=2, col=1)
    fig.add_trace(go.Scatter(x=x_3, y=del_3, mode='lines', name=f'udp {local_port_3}'), row=2, col=1)

    # Packets per second
    pps_1 = packets_ps(packet_1_in)
    pps_2 = packets_ps(packet_2_in)
    pps_3 = packets_ps(packet_3_in)
    pps_tcp = packets_ps(tcp_packet_in)

    fig.add_trace(go.Scatter(y=pps_1, mode='lines', name=f'udp {local_port_1}'), row=2, col=2)
    fig.add_trace(go.Scatter(y=pps_2, mode='lines', name=f'udp {local_port_2}'), row=2, col=2)
    fig.add_trace(go.Scatter(y=pps_3, mode='lines', name=f'udp {local_port_3}'), row=2, col=2)
    fig.add_trace(go.Scatter(y=pps_tcp, mode='lines', name=f'tcp port'), row=2, col=2)

    


    # Bytes per second
    pps_1 = bytes_ps(packet_1_in)
    pps_2 = bytes_ps(packet_2_in)
    pps_3 = bytes_ps(packet_3_in)
    pps_tcp =  bytes_ps(tcp_packet_in)

    fig.add_trace(go.Scatter(y=pps_1, mode='lines', name=f'udp {local_port_1}'), row=2, col=3)
    fig.add_trace(go.Scatter(y=pps_2, mode='lines', name=f'udp {local_port_2}'), row=2, col=3)
    fig.add_trace(go.Scatter(y=pps_3, mode='lines', name=f'udp {local_port_3}'), row=2, col=3)
    fig.add_trace(go.Scatter(y=pps_tcp, mode='lines', name=f'tcp port'), row=2, col=3)



    #fig.show()


    #packet lenght incoming
    len_1 = get_packet_length(packet_1_in)
    len_2 = get_packet_length(packet_2_in)
    len_3 = get_packet_length(packet_3_in)
    len_tcp = get_packet_length(tcp_packet_in)
    len_fig = go.Figure()
    len_fig.add_trace(go.Scatter(y=len_1, mode='lines', name=f'udp {local_port_1}'))
    len_fig.add_trace(go.Scatter(y=len_2, mode='lines', name=f'udp {local_port_2}'))
    len_fig.add_trace(go.Scatter(y=len_3, mode='lines', name=f'udp {local_port_3}'))
    len_fig.add_trace(go.Scatter(y=len_tcp, mode='lines', name=f'tcp'))

    len_fig.update_layout(title="Packet Length")

    len_fig.show()

    # Statistics

    ## histogram
    port1 = px.histogram(pps_1, x=pps_1)
    port1.update_layout(title='Historgram Packets PerSecond Port 1')
    port2 = px.histogram(pps_2)
    port2.update_layout(title='Statistics Packets PerSecond Port 2')


    ## packet length
    box1 = go.Figure()
    box1.add_trace(go.Box(y=len_1, name=f'{local_port_1}'))
    box1.add_trace(go.Box(y=len_2, name=f'{local_port_2}'))
    box1.add_trace(go.Box(y=len_tcp, name=f'tcp'))
    box1.update_layout(title='Box Plot of Packet lenth')
    
    box1.show()


    ## box plots packets per second
    box = go.Figure()
    box.add_trace(go.Box(y=pps_1, name=f'{local_port_1}'))
    box.add_trace(go.Box(y=pps_2, name=f'{local_port_2}'))
    box.update_layout(title='Box Plot of Packets PerSecond')

    box.show()

    # get packet loss
    get_packet_loss(packet_1_in)
    get_packet_loss(packet_2_in)
    get_packet_loss(packet_3_in)

    #seq1, x1 = get_seq_list(packet_1_in, time_offset)
    seq2, x2 = get_seq_list(packet_2_in, time_offset)
    print(seq2)
    #seq3, x3 = get_seq_list(packet_3_in, time_offset)

    seq = go.Figure()
    #seq.add_trace(go.Scatter(y=seq1, mode='lines', name=f'udp {local_port_1}'))
    seq.add_trace(go.Scatter(y=seq2, mode='lines', name=f'udp {local_port_2}'))
    #seq.add_trace(go.Scatter(y=seq3, mode='lines', name=f'udp {local_port_3}'))

    seq.show()

    print('finsihed')




def get_seq_list(packets, time_offset):

    ret = []
    time = []

    for pckt in packets:
        byte = pckt.getlayer(Raw).load
        if (byte[0] == 5):
            val = byte[1:3]
            val_int = int.from_bytes(val, "big")
            ret.append(val_int)
            time.append(pckt.time - time_offset)
    
    print()
    return ret, time


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



def get_inter_pckt_variation(packets):

    ret = []
    seq = []

    prev_seq = -1
    prev_time = -1


    for pckt in packets:
        byte = pckt
        if (prev_seq == -1):
            prev_seq = get_seq(pckt)
            prev_time = pckt.time

        else:
            
            diff = pckt.time - prev_time
            prev_time = pckt.time
            ret.append(diff)
            seq.append(get_seq(pckt))

    return ret, seq





def tcp_interpacket_variation(tcp_in, tcp_out, time_offset):
    seq_in = []
    x_in = []

    seq_out = []
    x_out = []


    for pckt in tcp_in:
        tcp_layer = pckt.getlayer(TCP)

        if (tcp_layer.seq not in seq_in):
            x_in.append(pckt.time - time_offset)
            seq_in.append(tcp_layer.seq)

    for pckt in tcp_out:
        tcp_layer = pckt.getlayer(TCP)

        if (tcp_layer.seq not in seq_out):
            x_out.append(pckt.time - time_offset)
            seq_out.append(tcp_layer.seq)

    return seq_in, x_in, seq_out, x_out
            

def packets_ps(packets):
    ret = []

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


def bytes_ps(packets):
    ret = []

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




def get_packet_length(packets):
    ret = []
    if (len(packets) > 0):
        for pckt in packets:
            ret.append(pckt.getlayer(IP).len)
    
    return ret





def get_latency(filename):

    packets = rdpcap(filename)

    zoom_addr = '134.224.45.47'
    zoom_port = 60860

    zoom_dst = []  # zoom -> dest
    zoom_src = []  # zoom -> src

    outgoing = {}
    time_y = []

    # ignore the first packet in each conversation
    i = 0
    for pckt in packets:
        if pckt.haslayer(TCP) and pckt.haslayer(IP):
            ip_layer = pckt.getlayer(IP)
            tcp_layer = pckt.getlayer(TCP)
            
            if (ip_layer.dst == zoom_addr):
                #print(f'{i}: Zoom dst -> sport: {tcp_layer.sport}, dport: {tcp_layer.dport}, seq: {tcp_layer.seq}, ack: {tcp_layer.ack}, len: {ip_layer.len}')
                zoom_dst.append(pckt)
                if (tcp_layer.ack in outgoing):
                    time = (abs(outgoing[tcp_layer.ack] - pckt.time)) *1000
                    time_y.append(time)
                    if (time > 1000):
                        print(time)


            if (ip_layer.src == zoom_addr):
                #print(f'Zoom src -> sport: {tcp_layer.sport}, dport: {tcp_layer.dport}, seq: {tcp_layer.seq}, ack: {tcp_layer.ack}, len: {ip_layer.len}')
                key = tcp_layer.seq + ip_layer.len - 40
                if (ip_layer.len != 40 and key not in outgoing):
                    outgoing[key] = pckt.time

                zoom_src.append(pckt)
        i = 1 + i

    print(f'Average: {sum(time_y) / len(time_y)}')
    x = np.linspace(0, len(time_y), len(time_y))
    plt.plot(x, time_y)
    plt.show()




def get_packet_loss(packets):

    '''
    Things to consider:
        - packets arrive out of order
    '''  
    pckt_loss = 0
    prev = -1

    for pckt in packets:
        byte = pckt.getlayer(Raw).load
        val = byte[1:3]
        val_int = int.from_bytes(val, "big")
        
        if prev == -1:
            prev = val_int
        else:
            if (val_int != prev + 1):
                print(val_int)
                pckt_loss = pckt_loss + 1
            prev = val_int


    
    print(f'loss: {pckt_loss}')   








    

    

if __name__ == "__main__":
    #process_pcap('Capture_analysis/cap1.pcapng')
    process_pcap('Capture_analysis/Base/cap2.pcapng', 'base_cap2')
    #get_latency('Capture_analysis/audio_only.pcapng')
    #get_packet_loss('Capture_analysis/audio_only.pcapng')

