#!/usr/bin/env python3
"""
merger.py
Merges flow features with payload features using bidirectional matching
Based on your merge.py logic
"""

import pandas as pd
import numpy as np
import time
import sys

def merge_flow_payload(flow_csv='flow.csv', payload_csv='payloads.csv', output_csv='merged_flow_payload.csv'):
    """Merge flow and payload features"""
    
    print("=" * 80)
    print("FLOW + PAYLOAD MERGER")
    print("=" * 80)
    
    start_time = time.time()
    
    # Load data
    print("\n[1/4] Loading CSV files...")
    try:
        flow_df = pd.read_csv(flow_csv, low_memory=False)
        print(f"    Flow data: {len(flow_df):,} rows")
    except Exception as e:
        print(f"    Error loading flow data: {e}")
        sys.exit(1)
    
    try:
        payload_df = pd.read_csv(payload_csv, low_memory=False)
        print(f"    Payload data: {len(payload_df):,} rows")
    except Exception as e:
        print(f"   ⚠️  No payload data found. Will proceed with flow features only.")
        payload_df = pd.DataFrame()
    
    # If no payload data, just return flow data
    if payload_df.empty:
        print("\n   No payload data to merge. Saving flow features only...")
        flow_df.to_csv(output_csv, index=False)
        print(f"\n Saved to: {output_csv}")
        return flow_df
    
    # Standardize column names
    print("\n[2/4] Standardizing columns...")
    flow_df.columns = flow_df.columns.str.strip().str.lower().str.replace(' ', '_')
    payload_df.columns = payload_df.columns.str.strip().str.lower().str.replace(' ', '_')
    
    # Clean payload data
    print("\n[3/4] Cleaning payload data...")
    
    # Remove rows with missing ports
    missing_ports = payload_df['src_port'].isna() | payload_df['dst_port'].isna()
    missing_count = missing_ports.sum()
    
    if missing_count > 0:
        print(f"   Found {missing_count} payloads with missing port info - removing...")
        payload_df = payload_df[~missing_ports].copy()
        print(f"   Remaining payloads: {len(payload_df)}")
    
    # Convert ports to int
    payload_df['src_port'] = payload_df['src_port'].astype(int)
    payload_df['dst_port'] = payload_df['dst_port'].astype(int)
    
    # Remove duplicate payloads
    payload_df['merge_key'] = (
        payload_df['src_ip'].astype(str) + '_' + 
        payload_df['dst_ip'].astype(str) + '_' + 
        payload_df['src_port'].astype(str) + '_' + 
        payload_df['dst_port'].astype(str)
    )
    
    duplicates = len(payload_df) - payload_df['merge_key'].nunique()
    payload_df = payload_df.drop_duplicates(subset='merge_key', keep='first')
    print(f"   Removed {duplicates} duplicate payloads")
    print(f"   Unique payloads: {len(payload_df)}")
    
    # Identify payload columns to merge
    payload_cols = [col for col in payload_df.columns 
                    if col not in ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'merge_key', 'timestamp']]
    
    print(f"   Payload columns to merge: {len(payload_cols)} columns")
    
    # Check for label column
    if 'label' in payload_cols:
        print(f"    Label column found in payload data")
    else:
        print(f"   ⚠️  Label column NOT found in payload data")
    
    # Create merge keys for flows
    print("\n[4/4] Merging datasets...")
    merge_start = time.time()
    
    # Forward direction
    flow_df['merge_key_fwd'] = (
        flow_df['src_ip'].astype(str) + '_' + 
        flow_df['dst_ip'].astype(str) + '_' + 
        flow_df['src_port'].astype(str) + '_' + 
        flow_df['dst_port'].astype(str)
    )
    
    # Reverse direction
    flow_df['merge_key_rev'] = (
        flow_df['dst_ip'].astype(str) + '_' + 
        flow_df['src_ip'].astype(str) + '_' + 
        flow_df['dst_port'].astype(str) + '_' + 
        flow_df['src_port'].astype(str)
    )
    
    # Rename label in flow_df to avoid conflict
    if 'label' in flow_df.columns:
        flow_df = flow_df.rename(columns={'label': 'flow_label'})
    
    # Merge forward direction first
    merged_df = flow_df.merge(
        payload_df[['merge_key'] + payload_cols],
        left_on='merge_key_fwd',
        right_on='merge_key',
        how='left',
        suffixes=('', '_payload')
    )
    
    # Try reverse direction for unmatched
    no_match_mask = merged_df['method'].isna()
    no_match_count = no_match_mask.sum()
    
    forward_matches = len(merged_df) - no_match_count
    print(f"   Forward direction matches: {forward_matches:,}")
    
    if no_match_count > 0:
        print(f"   Trying reverse direction for remaining {no_match_count:,} flows...")
        
        unmatched_flows = flow_df.loc[merged_df[no_match_mask].index]
        
        reverse_merge = unmatched_flows.merge(
            payload_df[['merge_key'] + payload_cols],
            left_on='merge_key_rev',
            right_on='merge_key',
            how='left',
            suffixes=('', '_rev')
        )
        
        reverse_matched_mask = reverse_merge['method'].notna()
        reverse_match_count = reverse_matched_mask.sum()
        
        if reverse_match_count > 0:
            matched_indices = merged_df[no_match_mask].index[reverse_matched_mask]
            
            for col in payload_cols:
                if col in reverse_merge.columns:
                    merged_df.loc[matched_indices, col] = reverse_merge.loc[reverse_matched_mask, col].values
        
        print(f"   Reverse direction matches: {reverse_match_count:,}")
    
    # Calculate final statistics
    total_matched = merged_df['method'].notna().sum()
    match_percentage = (total_matched / len(merged_df) * 100) if len(merged_df) > 0 else 0
    print(f"   Total matches: {total_matched:,} ({match_percentage:.1f}%)")
    print(f"   Merge time: {time.time() - merge_start:.2f}s")
    
    # Clean up
    print("\nFinalizing dataset...")
    
    # Drop merge keys
    cols_to_drop = ['merge_key_fwd', 'merge_key_rev', 'merge_key']
    for col in cols_to_drop:
        if col in merged_df.columns:
            merged_df = merged_df.drop(columns=col)
    
    # Drop duplicate columns
    dup_cols = [col for col in merged_df.columns if '_payload' in col or '_rev' in col]
    if dup_cols:
        merged_df = merged_df.drop(columns=dup_cols, errors='ignore')
    
    # Create indicator flag
    merged_df['has_http_payload'] = merged_df['method'].notna().astype(int)
    
    # Fill missing payload fields
    payload_text_cols = ['method', 'host', 'uri', 'user_agent', 'referer', 'content_type', 'full_url']
    for col in payload_text_cols:
        if col in merged_df.columns:
            merged_df[col] = merged_df[col].fillna('NONE')
    
    # Handle labels
    if 'label' in merged_df.columns and 'flow_label' in merged_df.columns:
        merged_df['final_label'] = merged_df['label'].fillna(merged_df['flow_label'])
        merged_df = merged_df.drop(columns=['label', 'flow_label'])
    elif 'label' in merged_df.columns:
        merged_df['final_label'] = merged_df['label'].fillna(-1)
        merged_df = merged_df.drop(columns=['label'])
    elif 'flow_label' in merged_df.columns:
        merged_df['final_label'] = merged_df['flow_label'].fillna(-1)
        merged_df = merged_df.drop(columns=['flow_label'])
    else:
        merged_df['final_label'] = -1
    
    # Rename final_label back to label
    merged_df = merged_df.rename(columns={'final_label': 'label'})
    
    # Ensure correct column order (flow features first, then payload features)
    flow_feature_cols = [
        'flow_id', 'src_port', 'dst_port', 'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
        'totlen_fwd_pkts', 'totlen_bwd_pkts', 'fwd_pkt_len_max', 'fwd_pkt_len_min',
        'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'bwd_pkt_len_max', 'bwd_pkt_len_min',
        'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'flow_byts_s', 'flow_pkts_s',
        'flow_iat_mean', 'flow_iat_std', 'flow_iat_max', 'flow_iat_min',
        'fwd_iat_tot', 'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_max', 'fwd_iat_min',
        'bwd_iat_tot', 'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_max', 'bwd_iat_min',
        'fwd_psh_flags', 'bwd_psh_flags', 'fwd_urg_flags', 'fwd_header_len', 'bwd_header_len',
        'fwd_pkts_s', 'bwd_pkts_s', 'pkt_len_min', 'pkt_len_max', 'pkt_len_mean',
        'pkt_len_std', 'pkt_len_var', 'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt',
        'psh_flag_cnt', 'ack_flag_cnt', 'down_up_ratio', 'pkt_size_avg',
        'fwd_seg_size_avg', 'bwd_seg_size_avg', 'fwd_byts_b_avg', 'fwd_pkts_b_avg',
        'fwd_blk_rate_avg', 'bwd_byts_b_avg', 'bwd_pkts_b_avg', 'bwd_blk_rate_avg',
        'subflow_fwd_pkts', 'subflow_fwd_byts', 'subflow_bwd_pkts', 'subflow_bwd_byts',
        'init_fwd_win_byts', 'init_bwd_win_byts', 'fwd_act_data_pkts', 'fwd_seg_size_min',
        'active_mean', 'active_std', 'active_max', 'active_min',
        'idle_mean', 'idle_std', 'idle_max', 'idle_min'
    ]
    
    payload_feature_cols = ['method', 'host', 'uri', 'full_url', 'user_agent', 'referer', 'content_type']
    label_cols = ['label', 'attack_type', 'subtype', 'severity']
    
    # Reorder columns
    ordered_cols = []
    for col in flow_feature_cols:
        if col in merged_df.columns:
            ordered_cols.append(col)
    
    for col in payload_feature_cols:
        if col in merged_df.columns:
            ordered_cols.append(col)
    
    for col in label_cols:
        if col in merged_df.columns:
            ordered_cols.append(col)
    
    # Add any remaining columns
    for col in merged_df.columns:
        if col not in ordered_cols:
            ordered_cols.append(col)
    
    merged_df = merged_df[ordered_cols]
    
    # Save
    print(f"\nSaving merged file...")
    merged_df.to_csv(output_csv, index=False)
    
    # Final report
    print("\n" + "=" * 80)
    print("MERGE COMPLETE")
    print("=" * 80)
    
    print(f"\nTotal execution time: {time.time() - start_time:.2f}s")
    print(f"Output file: {output_csv}")
    print(f"Total rows: {len(merged_df):,}")
    print(f"Total columns: {len(merged_df.columns)}")
    
    with_payload = merged_df['has_http_payload'].sum()
    without_payload = len(merged_df) - with_payload
    
    print(f"\nData Distribution:")
    print(f"  Flows WITH HTTP payload: {with_payload:,} ({with_payload/len(merged_df)*100:.1f}%)")
    print(f"  Flows WITHOUT HTTP payload: {without_payload:,} ({without_payload/len(merged_df)*100:.1f}%)")
    
    if 'label' in merged_df.columns:
        print(f"\nLabel Distribution:")
        print(merged_df['label'].value_counts())
    
    print("\n" + "=" * 80)
    
    return merged_df


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python merger.py <flow_csv> [payload_csv] [output_csv]")
        sys.exit(1)
    
    flow_csv = sys.argv[1]
    payload_csv = sys.argv[2] if len(sys.argv) > 2 else 'payloads.csv'
    output_csv = sys.argv[3] if len(sys.argv) > 3 else 'merged_flow_payload.csv'
    
    merge_flow_payload(flow_csv, payload_csv, output_csv)