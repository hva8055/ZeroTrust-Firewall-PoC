import pandas as pd
import os

NORMAL_LOG_PATH = "normal_data_2.log"   
HEAVY_ATTACK_LOG_PATH = "heavy_attack.log"
ATTACK_LOG_PATH = "attack_data.log"   
SAFE_PING_LOG = "ping_data.log"
MALWARE_LOG = "malware.log"
OUTPUT_CSV_PATH = "malware_dataset.csv" 


def parse_zeek_log(filepath):
    data_lines = []
    headers = []
    
    with open(filepath, 'r') as f:
        for line in f:
            if line.startswith("#"):
                if line.startswith("#fields"):
                    # Extract column names (remove '#fields', strip whitespace, split by tab)
                    headers = line.strip().split('\t')[1:]
                continue
            if not line.strip():
                continue
            data_lines.append(line.strip().split('\t'))
    df = pd.read_csv(filepath, sep='\t', comment='#', names=headers)
    return df
print("1. Loading Data...")

if os.path.exists(MALWARE_LOG):
    print(f"   Found Malware Log: {MALWARE_LOG}")
    df_malware = parse_zeek_log(MALWARE_LOG)
    
    df_malware['label'] = 2 
    
    print(f"   --> Loaded {len(df_malware)} rows.")
else:
    df_malware = pd.DataFrame()

if os.path.exists(SAFE_PING_LOG):
    print(f"   Found Safe Ping Log: {SAFE_PING_LOG}")
    df_safe_ping = parse_zeek_log(SAFE_PING_LOG)
    
    # CRITICAL: We force this to be 0 (Safe)
    df_safe_ping['label'] = 0 
    
    print(f"   --> Loaded {len(df_safe_ping)} rows.")
else:
    df_safe_ping = pd.DataFrame()

if os.path.exists(NORMAL_LOG_PATH):
    print(f"   Found Normal Log: {NORMAL_LOG_PATH}")
    df_normal = parse_zeek_log(NORMAL_LOG_PATH)
    df_normal['label'] = 0
    print(f"   --> Loaded {len(df_normal)} rows.")
else:
    print(f"ERROR: Could not find {NORMAL_LOG_PATH}")
    exit()
    
if os.path.exists(HEAVY_ATTACK_LOG_PATH):
    print(f"   Found Heavy Attack Log: {HEAVY_ATTACK_LOG_PATH}")
    df_heavy = parse_zeek_log(HEAVY_ATTACK_LOG_PATH)
    df_heavy['label'] = 1  # 1 = Malicious
    print(f"   --> Loaded {len(df_heavy)} rows.")
else:
    print(f"WARNING: Could not find {HEAVY_ATTACK_LOG_PATH}")
    df_heavy = pd.DataFrame()
if os.path.exists(ATTACK_LOG_PATH):
    print(f"   Found Attack Log: {ATTACK_LOG_PATH}")
    df_attack = parse_zeek_log(ATTACK_LOG_PATH)
    df_attack['label'] = 1  # 1 = Malicious
    print(f"   --> Loaded {len(df_attack)} rows.")
else:
    print(f"ERROR: Could not find {ATTACK_LOG_PATH}")
    exit()

print("2. Merging Datasets...")
df_final = pd.concat([df_normal, df_attack, df_heavy,df_safe_ping,df_malware], ignore_index=True)

df_final.replace('-', 0, inplace=True)
df_final.fillna(0, inplace=True)

print(f"3. Final Dataset Shape: {df_final.shape}")
print("   Sample Data:")
print(df_final[['id.orig_h', 'id.resp_h', 'service', 'label']].head())

df_final.to_csv(OUTPUT_CSV_PATH, index=False)
print(f"4. Success! Saved to {OUTPUT_CSV_PATH}")
