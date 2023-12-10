#!/usr/bin/env python

from scapy.all import *
import numpy as np
from tensorflow import keras
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
from sklearn.metrics import accuracy_score
import pandas as pd
import socket
import statistics
import time
import joblib
from datetime import datetime
import requests
import mysql.connector
import subprocess

# Loading the model
model = keras.models.load_model('/home/cybervault/Desktop/final/IDS/CyberVault_IDS')

# Loading scaler and label encoder
scaler = StandardScaler()
scaler.mean_ = np.load('/home/cybervault/Desktop/final/IDS/scaler_mean.npy')
scaler.scale_ = np.load('/home/cybervault/Desktop/final/IDS/scaler_scale.npy')
label_encoder = joblib.load('/home/cybervault/Desktop/final/IDS/label_encoder.pkl')

# Getting IP of the client
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 80))  # Connect to a known server
        client_ip = s.getsockname()[0]

# Names of the Features
column_names = [" Destination Port", "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max", 
                " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std", "Bwd Packet Length Max", 
                " Bwd Packet Length Min", " Bwd Packet Length Mean", " Bwd Packet Length Std", "Flow Bytes/s", 
                " Flow Packets/s", " Flow IAT Mean", " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", 
                " Fwd IAT Mean", " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean", 
                " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", " SYN Flag Count", " RST Flag Count", " PSH Flag Count", 
                " ACK Flag Count", " Down/Up Ratio", " Average Packet Size"," Avg Fwd Segment Size", " Avg Bwd Segment Size", 
                " Flow Duration", "Active Mean", " Active Std", " Active Max", " Active Min", "Idle Mean", " Idle Std", " Idle Max", " Idle Min"]

# Dataframe to store Packet Data
df = pd.DataFrame(columns=column_names)

# Database Configuration
db_config = {
    'host': 'localhost',
    'user': 'cybervault_user',
    'password': 'your_password',
    'database': 'cybervault_db'
}
# Function to connect to Database
def get_db_connection():
	return mysql.connector.connect(**db_config)

# IDS Table insert function
def insert_to_IDS(event_time, attack_type, src_ip, action_taken):
    try:
    	conn = get_db_connection()
    	cursor = conn.cursor()
    	
    	sql = "INSERT INTO IDS (eventTime, attackType, attackIP, actionTaken) VALUES (%s, %s, %s, %s)"
    	data_to_insert = (event_time, attack_type, src_ip, action_taken)
    	cursor.execute(sql, data_to_insert)
    	conn.commit()

    except Exception as e:
        print(f"Error inserting into the database: {e}")

    finally:
        cursor.close()
        conn.close()
 
# Firewall Table insert function        
def insert_to_FW(src_ip, dst_port, status):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = "INSERT INTO Firewall (eventIP, eventPort, status) VALUES (%s, %s, %s)"
        data_to_insert = (src_ip, dport, status)

        cursor.execute(sql, data_to_insert)
        conn.commit()

    except Exception as e:
        print(f"Error inserting into the database: {e}")

    finally:
        cursor.close()
        conn.close()        

# Log Table isert Function
def insert_to_LOG(event_time, status, desc):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        sql = "INSERT INTO Logs (logType, logTime, logStatus, logDescription) VALUES (%s, %s, %s, %s)"
        data_to_insert = ("IDS", event_time, status, desc)

        cursor.execute(sql, data_to_insert)
        conn.commit()

    except Exception as e:
        print(f"Error inserting into the database: {e}")

    finally:
        cursor.close()
        conn.close()

#Function to get mode from UI        
def get_ids_mode():
    try:
        response = requests.get('https://127.0.0.1:5000/IDS_get_mode', verify=False)
        if response.status_code == 200:
            return response.json()['mode']
    except Exception as e:
        print(str(e))

    # Return a default mode in case of an error
    return 'normal'

# Initialising Varaiable for Packet Processing
dst_port = 0
total_fwd_length = 0
total_bwd_length = 0
fwd_lengths = []
bwd_lengths = []

start_time = time.time()
total_bytes = 0
last_pkt_time = time.time()

fwd_iat_list = []
bwd_iat_list = []
flow_iat_list = []

fwd_IAT_total = 0
bwd_IAT_total = 0

total_pkts = 0
last_pkt_count_time = start_time

SYN_flag_count = 0
RST_flag_count = 0
PSH_flag_count = 0
ACK_flag_count = 0

down_count = 0
up_count = 0

active_times = []
idle_times = []

consecutive_classify = {}

# Function to reset Packet Data
def reset_var():
	global client_ip, df, model, label_encoder, scaler, total_fwd_length, total_bwd_length, fwd_lengths, bwd_lengths, start_time, total_bytes, last_pkt_time, total_pkts, last_pkt_count_time, fwd_IAT_total, bwd_IAT_total, SYN_flag_count, RST_flag_count, PSH_flag_count, ACK_flag_count, down_count, up_count, active_times, idle_times, consecutive_classify, dst_port 
	
	dst_port = 0
	total_fwd_length = 0
	total_bwd_length = 0
	fwd_lengths = []
	bwd_lengths = []
	start_time = time.time()
	total_bytes = 0
	last_pkt_time = time.time()
	fwd_iat_list = []
	bwd_iat_list = []
	flow_iat_list = []
	fwd_IAT_total = 0
	bwd_IAT_total = 0
	total_pkts = 0
	last_pkt_count_time = start_time
	SYN_flag_count = 0
	RST_flag_count = 0
	PSH_flag_count = 0
	ACK_flag_count = 0
	down_count = 0
	up_count = 0
	port = False
	active_times = []
	idle_times = []
	consecutive_classify = {}
    
# Function to Process Data
def process_packet(packet):
    
    global client_ip, df, model, label_encoder, scaler, total_fwd_length, total_bwd_length, fwd_lengths, bwd_lengths, start_time, total_bytes, last_pkt_time, total_pkts, last_pkt_count_time, fwd_IAT_total, bwd_IAT_total, SYN_flag_count, RST_flag_count, PSH_flag_count, ACK_flag_count, down_count, up_count, active_times, idle_times, consecutive_classify, port, dst_port 
    
    start_time = time.time()
    
    if TCP in packet:
    	dst_port = packet[TCP].dport
    elif UDP in packet:
    	dst_port = packet[UDP].dport
    	
    if TCP in packet:
        flags = packet[TCP].flags
        if flags & 0x02:
            SYN_flag_count += 1
        if flags & 0x04:
            RST_flag_count += 1
        if flags & 0x08:
            PSH_flag_count += 1
        if flags & 0x10:
            ACK_flag_count += 1
    
    if packet:
    	total_pkts += 1
    	
    if IP in packet and packet[IP].src == client_ip:
        total_fwd_length += packet[IP].len
        fwd_lengths.append(packet[IP].len)
        fwd_iat = time.time() - last_pkt_time
        fwd_iat_list.append(fwd_iat)
        flow_iat_list.append(fwd_iat)
        fwd_IAT_total += fwd_iat
        down_count += 1
        active_times.append(fwd_iat)
        
    elif IP in packet and packet[IP].dst == client_ip:
        total_bwd_length += packet[IP].len
        bwd_lengths.append(packet[IP].len)
        bwd_iat = time.time() - last_pkt_time
        bwd_iat_list.append(bwd_iat)
        flow_iat_list.append(bwd_iat)
        bwd_IAT_total += bwd_iat
        up_count += 1
        active_times.append(bwd_iat)
        
    if fwd_lengths:
        fwd_length_min = min(fwd_lengths)
        fwd_length_max = max(fwd_lengths)
        fwd_length_mean = statistics.mean(fwd_lengths)
        fwd_length_std = statistics.stdev(fwd_lengths) if len(fwd_lengths) > 1 else 0
    else:
        fwd_length_min = fwd_length_max = fwd_length_mean = fwd_length_std = 0

    if bwd_lengths:
        bwd_length_min = min(bwd_lengths)
        bwd_length_max = max(bwd_lengths)
        bwd_length_mean = statistics.mean(bwd_lengths)
        bwd_length_std = statistics.stdev(bwd_lengths) if len(bwd_lengths) > 1 else 0
    else:
        bwd_length_min = bwd_length_max = bwd_length_mean = bwd_length_std = 0
        
    if IP in packet:
        total_bytes += packet[IP].len
    
    elapsed_time = time.time() - start_time
    if elapsed_time > 0:
        flow_bytes_perSec = total_bytes / elapsed_time
    else: 
    	flow_bytes_perSec = 0    
        
    pkt_count_time = time.time()
    if pkt_count_time - last_pkt_count_time > 1:  # Calculate over a 1-second interval
        flow_pkts_perSec = total_pkts / (pkt_count_time - last_pkt_count_time)
        last_pkt_count_time = pkt_count_time
    else: 
    	flow_pkts_perSec = 0
    	last_pkt_count_time = pkt_count_time
    	    
    
    if flow_iat_list:
        flow_IAT_mean = statistics.mean(flow_iat_list)
        flow_IAT_std = statistics.stdev(flow_iat_list) if len(flow_iat_list) > 1 else 0
        flow_IAT_max = max(flow_iat_list)
        flow_IAT_min = min(flow_iat_list)
    else: 
    	flow_IAT_mean = flow_IAT_std = flow_IAT_max = flow_IAT_min = 0     
	       
    
    if fwd_iat_list:
        fwd_IAT_mean = statistics.mean(fwd_iat_list)
        fwd_IAT_std = statistics.stdev(fwd_iat_list) if len(fwd_iat_list) > 1 else 0
        fwd_IAT_max = max(fwd_iat_list)
        fwd_IAT_min = min(fwd_iat_list)
    else:
    	fwd_IAT_mean = fwd_IAT_std = fwd_IAT_max = fwd_IAT_min = 0
        

    if bwd_iat_list:
        bwd_IAT_mean = statistics.mean(bwd_iat_list)
        bwd_IAT_std = statistics.stdev(bwd_iat_list) if len(bwd_iat_list) > 1 else 0
        bwd_IAT_max = max(bwd_iat_list)
        bwd_IAT_min = min(bwd_iat_list)
    else:
    	bwd_IAT_mean = bwd_IAT_std = bwd_IAT_max = bwd_IAT_min = 0    
    
    if up_count > 0:
        down_up_ratio = down_count / up_count
    else: 
    	down_up_ratio = 0    
        
    if (len(fwd_lengths)+len(bwd_lengths)) > 0:
    	avg_pkt_size = (total_fwd_length + total_bwd_length) / (len(fwd_lengths) + len(bwd_lengths))
    else:
    	avg_pkt_size = 0	
    
    if fwd_lengths:
        avg_fwd_seg_size = total_fwd_length / len(fwd_lengths)
    else:
    	avg_fwd_seg_size = 0

    if bwd_lengths:
        avg_bwd_seg_size = total_bwd_length / len(bwd_lengths)
    else:
    	avg_bwd_seg_size = 0     
        
    end_time = time.time()
    flow_duration = end_time - start_time
    
    last_pkt_time = time.time()
    
    if len(active_times) > 1:
        idle_time = time.time() - last_pkt_time
        idle_times.append(idle_time)
    
    if active_times:
        active_mean = statistics.mean(active_times)
        active_std = statistics.stdev(active_times) if len(active_times) > 1 else 0
        active_max = max(active_times)
        active_min = min(active_times)
    else:
    	active_mean = active_std = active_max = active_min = 0    
   
    if idle_times:
        idle_mean = statistics.mean(idle_times)
        idle_std = statistics.stdev(idle_times) if len(idle_times) > 1 else 0
        idle_max = max(idle_times)
        idle_min = min(idle_times)
    else:
    	idle_mean = idle_std = idle_max = idle_min = 0  
          
# Dictionary to store current packet data    
    packet_dict = {
    	" Destination Port": dst_port,
        "Total Length of Fwd Packets": total_fwd_length,
        " Total Length of Bwd Packets": total_bwd_length,
        " Fwd Packet Length Max": fwd_length_max, 
        " Fwd Packet Length Min": fwd_length_min, 
        " Fwd Packet Length Mean": fwd_length_mean, 
        " Fwd Packet Length Std": fwd_length_std, 
        "Bwd Packet Length Max": bwd_length_max, 
        " Bwd Packet Length Min": bwd_length_min, 
        " Bwd Packet Length Mean": bwd_length_mean, 
        " Bwd Packet Length Std": bwd_length_std, 
        "Flow Bytes/s": flow_bytes_perSec, 
        " Flow Packets/s": flow_pkts_perSec, 
        " Flow IAT Mean": flow_IAT_mean, 
        " Flow IAT Std": flow_IAT_std, 
        " Flow IAT Max": flow_IAT_max, 
        " Flow IAT Min": flow_IAT_min, 
        "Fwd IAT Total": fwd_IAT_total, 
        " Fwd IAT Mean": fwd_IAT_mean, 
        " Fwd IAT Std": fwd_IAT_std, 
        " Fwd IAT Max": fwd_IAT_max, 
        " Fwd IAT Min": fwd_IAT_min, 
        "Bwd IAT Total": bwd_IAT_total, 
        " Bwd IAT Mean": bwd_IAT_mean, 
        " Bwd IAT Std": bwd_IAT_std, 
        " Bwd IAT Max": bwd_IAT_max, 
        " Bwd IAT Min": bwd_IAT_min, 
        " SYN Flag Count": SYN_flag_count, 
        " RST Flag Count": RST_flag_count, 
        " PSH Flag Count": PSH_flag_count, 
        " ACK Flag Count": ACK_flag_count, 
        " Down/Up Ratio": down_up_ratio, 
        " Average Packet Size": avg_pkt_size,
        " Avg Fwd Segment Size": avg_fwd_seg_size, 
        " Avg Bwd Segment Size": avg_bwd_seg_size, 
        " Flow Duration": flow_duration, 
        "Active Mean": active_mean, 
        " Active Std": active_std, 
        " Active Max": active_max, 
        " Active Min": active_min, 
        "Idle Mean": idle_mean, 
        " Idle Std": idle_std, 
        " Idle Max": idle_max, 
        " Idle Min": idle_min
    }
    

# Insert into Dataframe    
    df.loc[len(df)] = packet_dict

# Transforming Dataframe to scale
    df_scaled = scaler.transform(df[column_names])

# Predicitng the Class
    prediction_probs = model.predict(df_scaled)
    predicted_class = np.argmax(prediction_probs, axis=-1)
    
# Adding Label to Class    
    predicted_label = label_encoder.inverse_transform(predicted_class)
    
    print(f"Predicted Label: {predicted_label}") # printing label to console fro Debugging
    
    mode = get_ids_mode() # Getting current Mode
    print(mode)
    
    if mode == "aggressive":
        if IP in packet:
            src_ip = packet[IP].src
            if not (src_ip == client_ip):
                    if not (predicted_label[-1] == "BENIGN"):
                        if src_ip in consecutive_classify:
                            if consecutive_classify[src_ip]['prev_class'] == predicted_label[-1]:
                                consecutive_classify[src_ip]['count'] += 1
                                if consecutive_classify[src_ip]['count'] >= 5: # Waiting for Multiple classifications from same IP to avoid False classification
                                    # Detect and Block attack (aggressive mode)
                                    if consecutive_classify[src_ip]['prev_class'] == "Bot":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip]) # Blocking IP using UFW
                                        print(f"Bot attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"Bot attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                         
                                    elif consecutive_classify[src_ip]['prev_class'] == "DDoS":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"DDoS attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"DDoS attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                                
                                    elif consecutive_classify[src_ip]['prev_class'] == "PortScan":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"Port Scan detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"Port Scan detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "Infiltration":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"Infiltrattion attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"Infiltration attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "FTP-Patator":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"FTP-Patator attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"FTP-Patator attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "SSH-Patator":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"SSH-Patator attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"SSH-Patator attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS slowloris":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"DoS slowloris attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"DoS slowloris attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                                
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS Slowhttptest":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"DoS slowhttptest attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"DoS slowhttptest attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS Hulk":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"DoS Hulk attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"DoS Hulk attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS GoldenEye":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"DoS GoldenEye attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"DoS GoldenEye attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif consecutive_classify[src_ip]['prev_class'] == "Heartbleed":
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"Heartbleed attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"Heartbleed attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                        
                                    elif "Web Attack" in consecutive_classify[src_ip]['prev_class']:
                                        subprocess.run(['sudo', 'ufw', 'deny', 'from', src_ip])
                                        print(f"Web attack detected: {src_ip} Blocked")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = f"Web attack detected: {src_ip} Blocked"
                                        status = "Blocked"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                        insert_to_FW(src_ip, dst_port, status)
                                        insert_to_LOG(event_time, status, action_taken)
                                                                                        
                            else:
                                consecutive_classify[src_ip]['prev_class'] = predicted_label[-1]
                                consecutive_classify[src_ip]['count'] = 1
                        else:
                            # This is the first classification for this IP
                            consecutive_classify[src_ip] = {'prev_class': predicted_label[-1], 'count': 1}

    if mode == "normal":
        if IP in packet:
            src_ip = packet[IP].src
            if not (src_ip == client_ip):
                    if not (predicted_label[-1] == "BENIGN"):
                        if src_ip in consecutive_classify:
                            if consecutive_classify[src_ip]['prev_class'] == predicted_label[-1]:
                                consecutive_classify[src_ip]['count'] += 1
                                if consecutive_classify[src_ip]['count'] >= 5: # Waiting for Multiple classifications from same IP to avoid False classification
                                    # Inform the user of the attack (normal mode)
                                    if consecutive_classify[src_ip]['prev_class'] == "Bot":
                                        print(f"Bot attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "DDoS":
                                        print(f"DDoS attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "PortScan":
                                        print(f"Port Scan attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "Infiltration":
                                        print(f"Infiltration attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "FTP-Patator":
                                        print(f"FTP-Patator attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "SSH-Patator":
                                        print(f"SSH-Patator attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS slowloris":
                                        print(f"DoS slowloris attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS Slowhttptest":
                                        print(f"Dos Slowhttptest attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS Hulk":
                                        print(f"DoS Hulk attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "DoS GoldenEye":
                                        print(f"DoS GoldenEye attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif consecutive_classify[src_ip]['prev_class'] == "Heartbleed":
                                        print(f"Heartbleed attack detected from {src_ip}!")
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                                    elif "Web Attack" in consecutive_classify[src_ip]['prev_class']:
                                        print(f"Web attack detected from {src_ip}!")	
                                        attack_type = predicted_label[-1]
                                        event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                        action_taken = "None"
                                        insert_to_IDS(event_time, attack_type, src_ip, action_taken)
                            else:
                                consecutive_classify[src_ip]['prev_class'] = predicted_label[-1]
                                consecutive_classify[src_ip]['count'] = 1
                        else:
                            # This is the first classification for this IP
                            consecutive_classify[src_ip] = {'prev_class': predicted_label[-1], 'count': 1}
    
    with open("IDS_output.txt", "w") as file:   # writing to a file for Debugging
    	file.write(datetime.now().strftime("%d/%m/%Y, %H:%M:%S\n"))
    	file.write(f"Predicted Label: {predicted_label}")
    	
    if time.time() % (5 * 60) < 1:  # Check every second if it's time to reset (adjust as needed)
        reset_var()	




interface = "wlP2p33s0"  # Change this to the appropriate interface

try:
	sniff(iface=interface, prn=process_packet) # Sniffing packets from interface to process
	
except Exception as e:
	print(str(e));

