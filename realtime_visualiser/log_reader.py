import matplotlib.pyplot as plt
import matplotlib.dates as matdates
import numpy as np
import pdb
import datetime
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json

plot_key = {}
index = -1
pps = []
mbps = []
plen = []


def plot_log(filename):

    global index
    global plot_key, pps, mbps, plen

    file = open(filename, 'r')
    lines = file.read().splitlines()


    media = {}



    for line in lines:
        if (len(line.split('DEBUG:root:Log: ')) < 2):
            continue
        log_str = line.split('DEBUG:root:Log: ')[1]
        log_obj = json.loads(log_str)

        data = log_obj['sent']
        

        for key in data:
            info = data[key]['info']
            if (info['protocol'] != 'UDP'):
                continue

            update_plot_key(key)
            i = plot_key[key]

            #print(key, index)

            media[key] = data[key]['data']['media']

            pps[i].append(data[key]['data']['pps'])
            mbps[i].append(data[key]['data']['mbps'])
            plen[i].append(data[key]['data']['len'])

    
    fig = make_subplots(rows=3, cols=1, subplot_titles=('PPS', 'LEN', 'MBPS'))

    fig.add_trace(go.Scatter(y=pps[0], mode='lines', name=f'key1'), row=1, col=1)
    fig.add_trace(go.Scatter(y=pps[1], mode='lines', name=f'key2'), row=1, col=1)
    fig.add_trace(go.Scatter(y=pps[2], mode='lines', name=f'key3'), row=1, col=1)


    fig.add_trace(go.Scatter(y=plen[0], mode='lines', name=f'key1'), row=2, col=1)
    fig.add_trace(go.Scatter(y=plen[1], mode='lines', name=f'key2'), row=2, col=1)
    fig.add_trace(go.Scatter(y=plen[2], mode='lines', name=f'key3'), row=2, col=1)

    fig.add_trace(go.Scatter(y=mbps[0], mode='lines', name=f'key1'), row=3, col=1)
    fig.add_trace(go.Scatter(y=mbps[1], mode='lines', name=f'key2'), row=3, col=1)
    fig.add_trace(go.Scatter(y=mbps[2], mode='lines', name=f'key3'), row=3, col=1)

    print(media)

    fig.show()

def update_plot_key(key):

    
    global index
    global plot_key, pps, mbps, plen
    
    if (key not in plot_key):
        #print(key, index, plot_key)
        plot_key[key] = index +1
        index = index+1
        pps.append([])
        mbps.append([])
        plen.append([])



if __name__ == "__main__":
    #process_pcap('Capture_analysis/cap1.pcapng')
    plot_log('logs/2021_08_09_14_32_51.log')
    
    #get_latency('Capture_analysis/audio_only.pcapng')
    #get_packet_loss('Capture_analysis/audio_only.pcapng')
