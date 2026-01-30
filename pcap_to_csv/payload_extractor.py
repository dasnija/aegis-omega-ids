#!/usr/bin/env python3
"""
payload_extractor.py
Extracts HTTP payload features from PCAP using tshark
Based on your payloadsCreatorWithlabel.py
"""

import subprocess
import pandas as pd
import json
import re
import os
import shutil
import time
import sys
import io

# Fix Windows console encoding to support Unicode characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

def find_tshark():
    """Locate tshark executable on Windows"""
    if shutil.which("tshark"):
        return "tshark"
    
    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'Wireshark', 'tshark.exe'),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'), 'Wireshark', 'tshark.exe'),
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    # Try Unix paths
    unix_paths = ['/usr/bin/tshark', '/usr/local/bin/tshark']
    for path in unix_paths:
        if os.path.exists(path):
            return path
    
    raise FileNotFoundError(
        "tshark not found! Please install Wireshark.\n"
        "Windows: https://www.wireshark.org/download.html\n"
        "Linux: sudo apt-get install tshark"
    )


def load_labels_with_recovery(labels_file):
    """Load labels from JSONL with smart recovery for malformed JSON"""
    print(f"\n[1/2] Loading labels from {labels_file}...")
    
    if not os.path.exists(labels_file):
        print(f"   ⚠️  Labels file not found. Will extract payloads without labels.")
        return pd.DataFrame()
    
    labels_list = []
    error_count = 0
    recovered_count = 0
    success_count = 0
    
    with open(labels_file, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
                
            try:
                data = json.loads(line)
                labels_list.append(data)
                success_count += 1
                
            except json.JSONDecodeError:
                error_count += 1
                
                # Smart recovery
                try:
                    ts_match = re.search(r'"timestamp":([\d.]+)', line)
                    label_match = re.search(r'"label":(\d)', line)
                    attack_match = re.search(r'"attack_type":"([^"]+)"', line)
                    subtype_match = re.search(r'"subtype":"([^"]+)"', line)
                    sev_match = re.search(r'"severity":(\d)', line)
                    sess_match = re.search(r'"session":(\d+)', line)
                    url_match = re.search(r'"url":"(.+)"}\s*$', line)
                    
                    if ts_match and label_match:
                        recovered_data = {
                            'timestamp': float(ts_match.group(1)),
                            'label': int(label_match.group(1)),
                            'attack_type': attack_match.group(1) if attack_match else 'unknown',
                            'subtype': subtype_match.group(1) if subtype_match else 'unknown',
                            'severity': int(sev_match.group(1)) if sev_match else 0,
                            'session': int(sess_match.group(1)) if sess_match else -1,
                            'url': url_match.group(1) if url_match else ''
                        }
                        labels_list.append(recovered_data)
                        recovered_count += 1
                
                except Exception:
                    pass
    
    if not labels_list:
        print(f"   ⚠️  No valid labels found")
        return pd.DataFrame()
    
    labels_df = pd.DataFrame(labels_list)
    labels_df['timestamp'] = pd.to_datetime(labels_df['timestamp'], unit='s')
    
    print(f"   ✓ Parsed: {success_count:,}, Recovered: {recovered_count:,}, Failed: {error_count - recovered_count:,}")
    print(f"   ✓ Total usable labels: {len(labels_list):,}")
    
    if 'label' in labels_df.columns:
        benign = (labels_df['label'] == 0).sum()
        attack = (labels_df['label'] == 1).sum()
        print(f"   ✓ Benign: {benign:,}, Attack: {attack:,}")
    
    return labels_df


def extract_http_payloads_tshark(pcap_file, tshark_path):
    """Extract HTTP payloads using tshark"""
    print(f"\n[2/2] Extracting HTTP payloads with tshark...")
    
    tshark_cmd = [
        tshark_path,
        "-r", pcap_file,
        "-Y", "http.request",
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "tcp.srcport",
        "-e", "ip.dst",
        "-e", "tcp.dstport",
        "-e", "http.request.method",
        "-e", "http.host",
        "-e", "http.request.uri",
        "-e", "http.request.full_uri",
        "-e", "http.user_agent",
        "-e", "http.referer",
        "-e", "http.content_type",
        "-e", "http.content_length",
        "-E", "separator=|",
        "-E", "occurrence=f"
    ]
    
    try:
        start_time = time.time()
        
        process = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
           stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='ignore',
            bufsize=2
        )
        
        raw_lines = []
        line_count = 0
        last_update = time.time()
        
        while True:
            line = process.stdout.readline()
            if not line:
                break
                
            line = line.strip()
            if line:
                raw_lines.append(line)
                line_count += 1
                
                if line_count % 1000 == 0 or (time.time() - last_update) >= 2:
                    print(f"   Reading: {line_count:,} HTTP requests...", end='\r')
                    last_update = time.time()
        
        process.wait()
        elapsed_time = time.time() - start_time
        
        print(f"\n   ✓ Extracted {len(raw_lines):,} HTTP requests in {elapsed_time:.1f}s")
        
        if len(raw_lines) == 0:
            print("   ⚠️  No HTTP data found in PCAP")
            return []
        
        return raw_lines
        
    except Exception as e:
        print(f"\n   Error: {e}")
        return []


def parse_http_lines(raw_lines):
    """Parse tshark output into structured data"""
    print(f"\n   Processing HTTP data...")
    
    extracted_rows = []
    processed = 0
    start_time = time.time()
    last_update = time.time()
    
    for line in raw_lines:
        if not line.strip():
            continue
        
        try:
            parts = line.split('|')
            if len(parts) < 6:
                continue
            
            timestamp = float(parts[0]) if parts[0] else 0.0
            src_ip = parts[1] if len(parts) > 1 else ""
            src_port = parts[2] if len(parts) > 2 else ""
            dst_ip = parts[3] if len(parts) > 3 else ""
            dst_port = parts[4] if len(parts) > 4 else ""
            method = parts[5] if len(parts) > 5 else ""
            host = parts[6] if len(parts) > 6 else ""
            uri = parts[7] if len(parts) > 7 else ""
            full_url = parts[8] if len(parts) > 8 else ""
            user_agent = parts[9] if len(parts) > 9 else ""
            referer = parts[10] if len(parts) > 10 else ""
            content_type = parts[11] if len(parts) > 11 else ""
            content_length = parts[12] if len(parts) > 12 else ""
            
            if not method:
                continue
            
            # Build full URL if missing
            if not full_url and host and uri:
                proto = "https" if dst_port == "443" else "http"
                full_url = f"{proto}://{host}{uri}"
            
            extracted_rows.append({
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'method': method,
                'host': host,
                'uri': uri,
                'user_agent': user_agent,
                'referer': referer,
                'content_type': content_type,
                'full_url': full_url
            })
            
            processed += 1
            
            if processed % 500 == 0 or (time.time() - last_update) >= 2:
                print(f"   Processing: {processed:,}/{len(raw_lines):,} ({processed/len(raw_lines)*100:.1f}%)", end='\r')
                last_update = time.time()
                
        except Exception as e:
            continue
    
    print(f"\n   ✓ Processed {len(extracted_rows):,} HTTP records")
    return extracted_rows


def match_with_labels(payloads_df, labels_df):
    """Match payloads with labels using timestamp"""
    if labels_df.empty:
        print("\n   ⚠️  No labels to match")
        return payloads_df
    
    print(f"\n   Matching with labels...")
    
    payloads_df['timestamp'] = pd.to_datetime(payloads_df['timestamp'], unit='s')
    payloads_df = payloads_df.sort_values('timestamp').reset_index(drop=True)
    labels_df = labels_df.sort_values('timestamp').reset_index(drop=True)
    
    # Merge using nearest timestamp within 2 seconds
    merged = pd.merge_asof(
        payloads_df,
        labels_df[['timestamp', 'label', 'attack_type', 'subtype', 'severity']],
        on='timestamp',
        direction='nearest',
        tolerance=pd.Timedelta('2s')
    )
    
    # Fill unmatched
    merged['label'] = merged['label'].fillna(-1).astype(int)
    merged['attack_type'] = merged['attack_type'].fillna('unknown')
    merged['subtype'] = merged['subtype'].fillna('unknown')
    merged['severity'] = merged['severity'].fillna(0).astype(int)
    
    matched = (merged['label'] != -1).sum()
    match_rate = (matched / len(merged)) * 100 if len(merged) > 0 else 0
    
    print(f"   ✓ Matched: {matched:,}/{len(merged):,} ({match_rate:.1f}%)")
    
    if matched > 0:
        benign = (merged['label'] == 0).sum()
        attack = (merged['label'] == 1).sum()
        print(f"   ✓ Benign: {benign:,}, Attack: {attack:,}")
    
    return merged


def extract_payload_features(pcap_file, labels_file=None, output_csv='payloads.csv'):
    """Main function to extract payload features"""
    print("=" * 80)
    print("HTTP PAYLOAD EXTRACTOR")
    print("=" * 80)
    
    start_time = time.time()
    
    # Find tshark
    try:
        tshark_path = find_tshark()
        print(f"✓ Found tshark: {tshark_path}")
    except FileNotFoundError as e:
        print(e)
        sys.exit(1)
    
    # Load labels (if available)
    labels_df = pd.DataFrame()
    if labels_file:
        labels_df = load_labels_with_recovery(labels_file)
    
    # Extract HTTP payloads
    raw_lines = extract_http_payloads_tshark(pcap_file, tshark_path)
    
    if not raw_lines:
        print("\n⚠️  No HTTP payloads extracted")
        return pd.DataFrame()
    
    # Parse HTTP data
    extracted_rows = parse_http_lines(raw_lines)
    
    if not extracted_rows:
        print("\n⚠️  No valid HTTP data parsed")
        return pd.DataFrame()
    
    # Create dataframe
    payloads_df = pd.DataFrame(extracted_rows)
    
    # Match with labels
    if not labels_df.empty:
        payloads_df = match_with_labels(payloads_df, labels_df)
    else:
        # Add empty label columns
        payloads_df['label'] = -1
        payloads_df['attack_type'] = 'unknown'
        payloads_df['subtype'] = 'unknown'
        payloads_df['severity'] = 0
    
    # Save
    payloads_df.to_csv(output_csv, index=False)
    
    print(f"\n{'='*80}")
    print(f"✓ Payload extraction complete in {time.time() - start_time:.2f}s")
    print(f"✓ Saved to: {output_csv}")
    print(f"✓ Total payloads: {len(payloads_df):,}")
    print(f"{'='*80}\n")
    
    return payloads_df


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python payload_extractor.py <pcap_file> [labels_file] [output_csv]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    labels_file = sys.argv[2] if len(sys.argv) > 2 else None
    output_csv = sys.argv[3] if len(sys.argv) > 3 else 'payloads.csv'
    
    extract_payload_features(pcap_file, labels_file, output_csv)