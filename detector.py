import pandas as pd
import pickle
import time
import os
import subprocess
import sys

# --- CONFIGURATION ---
MODEL_PATH = "firewall_ai_model.pkl"
ZEEK_LOG_PATH = "/opt/zeek/logs/current/conn.log"
PACKET_COUNT = 0
BLOCKED_SCANNERS = set()
REDIRECTED_CLIENTS = set()

print("1. Loading AI Model...")

if not os.path.exists(MODEL_PATH):
    print(f"ERROR: Model file {MODEL_PATH} not found. Run 2_train_model.py first!")
    sys.exit(1)

with open(MODEL_PATH, "rb") as f:
    saved_data = pickle.load(f)
    model = saved_data["model"]
    encoders = saved_data["encoders"]
    model.n_jobs = 1 

print("   --> Model Loaded Successfully.")
print(f"2. Monitoring Real-Time Traffic at: {ZEEK_LOG_PATH}")
print("   (Press Ctrl+C to stop)")
print("-" * 50)

def block_attacker(ip_address):
    # Don't ban the same person twice
    if ip_address in BLOCKED_SCANNERS:
        return 
    print(f"\n\033[91m[!] INBOUND SCAN DETECTED from {ip_address}!\033[0m")
    print(f"   [+] Action: Dropping all traffic from this IP.")
    print(f"\n\033[91m   [!!!] BLOCKING IP: {ip_address} in Firewall...\033[0m")
    
    cmd_input = f"iptables -I INPUT -s {ip_address} -j DROP"
    subprocess.run(cmd_input, shell=True)
    BLOCKED_SCANNERS.add(ip_address)
    
def redirect_malware(infected_ip):
    """ Action for Prediction 2: Outbound Malware/C2 """
    if infected_ip in REDIRECTED_CLIENTS:
        return
        
    HONEYPOT_IP = "192.168.10.200"
    print('honey_pot')
    
    print(f"\n\033[95m[!!!] OUTBOUND MALWARE DETECTED from internal IP {infected_ip}!\033[0m")
    print(f"   [+] Action: Silently routing malware to Honeypot ({HONEYPOT_IP})...")
    
    # Deception block: Reroute the infected machine's outbound traffic into the Honeypot
    cmd_redirect = f"sudo iptables -t nat -I PREROUTING -s {infected_ip} -j DNAT --to-destination {HONEYPOT_IP}"
    subprocess.run(cmd_redirect, shell=True)
    
    REDIRECTED_CLIENTS.add(infected_ip)

# --- 3. PREDICTION ENGINE ---
def parse_and_predict(line):
    global PACKET_COUNT  
    
    try:
        parts = line.strip().split('\t')
        
        if len(parts) < 12: return 

        timestamp = time.strftime("%H:%M:%S", time.localtime(float(parts[0])))
        src_ip = parts[2]
        dst_ip = parts[4]

        features = {
            'id.resp_p':  float(parts[5]),
            'proto':      parts[6],
            'service':    parts[7],
            'conn_state': parts[11],
            'orig_bytes': parts[9],
            'resp_bytes': parts[10]
        }

        if features['orig_bytes'] == '-': features['orig_bytes'] = 0
        if features['resp_bytes'] == '-': features['resp_bytes'] = 0
        
        features['orig_bytes'] = float(features['orig_bytes'])
        features['resp_bytes'] = float(features['resp_bytes'])

        def safe_encode(encoder, value):
            try:
                return encoder.transform([value])[0]
            except:
                return 0 

        features['proto'] = safe_encode(encoders['proto'], features['proto'])
        features['service'] = safe_encode(encoders['service'], features['service'])
        features['conn_state'] = safe_encode(encoders['conn_state'], features['conn_state'])

        df_input = pd.DataFrame([features])
        
        prediction = model.predict(df_input)[0] 
        PACKET_COUNT += 1
        print(prediction)
        if prediction == 1:
            print(" " * 80, end='\r') 
            print(f"\033[91m{timestamp:<20} | {src_ip:<15} | {dst_ip:<15} | [!!! ATTACK !!!]\033[0m")
            block_attacker(src_ip)
        elif prediction == 2:
            print(f"\033[95m[!!!] OUTBOUND MALWARE (C2) from {src_ip} to {dst_ip}\033[0m")
            # Call the new Honeypot Redirect function!
            redirect_malware(src_ip)
        else:
            print(f"   [+] Monitoring Real-Time... Packets Scanned: {PACKET_COUNT} | Last IP: {src_ip:<15}", end='\r', flush=True)

    except Exception:
        pass

def follow(thefile):
    thefile.seek(0, os.SEEK_END) 
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1) 
            continue
        yield line

# --- MAIN EXECUTION ---
try:
    with open(ZEEK_LOG_PATH, "r") as logfile:
        for line in follow(logfile):
            if not line.startswith("#"): 
                parse_and_predict(line)
except PermissionError:
    print("\n[ERROR] Permission Denied!")
    print("You must run this script with 'sudo'.")
    print("Try: sudo python3 3_live_detector.py")
except KeyboardInterrupt:
    print("\n\n[+] Stopping IDS. Stay safe!")
