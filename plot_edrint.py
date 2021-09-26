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
import argparse
import csv

plot_key = {}
index = -1
pps = []
mbps = []
plen = []


def plot_log(filename, pcapname):

    global index
    global plot_key, pps, mbps, plen

    file = open(filename, 'r')
    lines = file.read().splitlines()

    mediaMap = ['buffer', 'audio', 'video', 'content', 'unknown', 'inactive']

    media = {}
    time = 0

    flow_key = {}

    plot_title = ["TCP Latency"]

    i = 3

    for line in lines:
        log = json.loads(line)
        topic = log["Topic"]
        if (topic == 'zoom_pps'):
            name = log["Event"]["Header"]["DstPort"]

            if (name not in flow_key):
                flow_key[name] = {
                    "media": log["Event"]["Media"],
                    "mbps": log['Event']['ListMBPS'],
                    "pps": log['Event']['ListPPS']
                }
            
            #fig.add_trace(go.Scatter(y=log['Event']['ListMBPS'], mode='lines', name=f'BPS {mediaMap[flow_key[name]["media"]]}'), row=i, col=1)
            #fig.add_trace(go.Scatter(y=log['Event']['ListPPS'], mode='lines', name=f'PPS {mediaMap[flow_key[name]["media"]]}'), row=i, col=1)

            #i+= 2
            

    i = 2
    for line in lines:
        log = json.loads(line)
        topic = log["Topic"]
        protocol = log['Event']['Header']['Protocol']
        if (topic == 'zoom_loss'):

            name = log["Event"]["Header"]["DstPort"]

            base_50 = [50] * len(log['Event']['ListLoss'])
            base_25 = [25] * len(log['Event']['ListLoss'])

            flow_key[name]["loss"] = log['Event']['ListLoss']
            time = len(flow_key[name]["loss"])
           
            #fig.add_trace(go.Scatter(y=log['Event']['ListLoss'], mode='lines', name=f'Loss {mediaMap[flow_key[name]["media"]]}'), row=i, col=1)
            #fig.add_trace(go.Scatter(y=base_50, mode='lines', marker_color='rgb(255,0,0)', name=f'Base Loss'), row=i, col=1)
            #fig.add_trace(go.Scatter(y=base_25, mode='lines', marker_color='rgb(255,255,0)', name=f'Base Loss'), row=i, col=1)

            i += 2

        if (topic == 'telemetry.tcp.rtt'):
            base_lat = [150] * len(log['Event']['RTTMS'])
            #fig.add_trace(go.Scatter(y=log['Event']['RTTMS'], mode='lines', name='Latency'), row=1, col=1)
            #fig.add_trace(go.Scatter(y=base_lat, mode='lines', marker_color='rgb(255,0,0)', name=f'Base Latency'), row=1, col=1)
            flow_key["tcp"] = {}
            flow_key["tcp"]["latency"] = log['Event']['RTTMS']


    i = 3
    fig = make_subplots(rows=6, cols=1, subplot_titles=('TCP Latency', 'Measured QOE', 'UDP Audio Loss',  'Data Audio Rate', 'Calculated QOE'))

    # plot measured qoe

    exp_name = (pcapname.split('.'))[0]

    f = open(f'../../captures/zoom/experiments/{exp_name}.csv')

    r = csv.reader(f)

    j = 0

    measured_qoe = []

    for row in r:
        start = int(row[0]) * 60 + int(row[1])
        end = int(row[2]) * 60 + int(row[3])

        #print('qoe: ', start, end)

        #print(row)

        while (j != start):
            measured_qoe.append(0)
            j += 1

        print('finish 0')
    
        while (j != end):
            measured_qoe.append(1)
            j += 1
        print('finish 1')

    while (j != time):
        measured_qoe.append(0)
        j+=1

    measured_good_qoe = [1 - x for x in measured_qoe]



    fig.add_trace(go.Scatter(y=measured_qoe, marker_color='rgb(255,0,0)', fill="tozeroy"), row=2, col=1)
    fig.add_trace(go.Scatter(y=measured_good_qoe, marker_color='rgb(0,255,0)', fill="tozeroy"), row=2, col=1)

    for flow in flow_key:
        #(flow_key[flow])

        if (flow == "tcp"):
            lat = flow_key[flow]["latency"]
            fig.add_trace(go.Scatter(y=lat, mode='lines', name='Latency'), row=1, col=1)

        else:
            media_num = flow_key[flow]["media"]


            if (media_num == 1):
                loss = flow_key[flow]["loss"]
                time = len(loss)
                pps = flow_key[flow]["pps"]
                mbps = flow_key[flow]["mbps"]
                fig.add_trace(go.Scatter(y=loss, mode='lines', name=f'Loss: {mediaMap[media_num]}'), row=i, col=1)
                fig.add_trace(go.Scatter(y=base_50, mode='lines', marker_color='rgb(255,0,0)', name=f'Base Loss'), row=i, col=1)
                fig.add_trace(go.Scatter(y=base_25, mode='lines', marker_color='rgb(255,255,0)', name=f'Base Loss'), row=i, col=1)
                i += 1
                fig.add_trace(go.Scatter(y=pps, mode='lines', name=f'Pps: {mediaMap[media_num]}'), row=i, col=1)
                fig.add_trace(go.Scatter(y=mbps, mode='lines', name=f'Mbps: {mediaMap[media_num]}'), row=i, col=1)
                i += 1

    




    
    fig.update_layout(width=1500, height=1500, title_text=f"Pcap: {pcapname}")


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
    #plot_log('logs/2021_08_09_14_32_51.log')


    parser = argparse.ArgumentParser()
    parser.add_argument('--file', type=str, required=True)
    args = parser.parse_args()

    dir_path = '../../ThesisB/edrint/cmd/edrint/files/dumps/'
    file_path = dir_path + args.file

    plot_log(file_path, args.file)
    
    #get_latency('Capture_analysis/audio_only.pcapng')
    #get_packet_loss('Capture_analysis/audio_only.pcapng')
