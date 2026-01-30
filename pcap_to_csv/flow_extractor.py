#!/usr/bin/env python3
"""
flow_extractor.py
Extracts flow-level features from PCAP files using Scapy
Replaces CICFlowMeter GUI with automated extraction
"""

import pandas as pd
import numpy as np
from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict
import time
import sys
import logging

# Create module logger
logger = logging.getLogger(__name__)

class FlowFeatureExtractor:
    def __init__(self):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'timestamps': [],
            'lengths': [],
            'flags': [],
            'directions': [],
            'window_sizes': [],
            'header_lens': [],
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None
        })
    
    def create_flow_id(self, pkt):
        """Create bidirectional flow identifier"""
        if IP not in pkt:
            return None, None, None, None, None
        
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            proto = 6
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            proto = 17
        else:
            return None, None, None, None, None
        
        # Create bidirectional flow ID
        flow_tuple = tuple(sorted([
            (src_ip, src_port),
            (dst_ip, dst_port)
        ]))
        
        flow_id = f"{flow_tuple[0][0]}:{flow_tuple[0][1]}-{flow_tuple[1][0]}:{flow_tuple[1][1]}-{proto}"
        
        # Determine original direction
        is_forward = (src_ip, src_port) == flow_tuple[0]
        
        return flow_id, src_ip, dst_ip, src_port, dst_port
    
    def determine_direction(self, pkt, flow_id):
        """Determine if packet is forward (0) or backward (1)"""
        if len(self.flows[flow_id]['packets']) == 0:
            return 0
        
        first_pkt = self.flows[flow_id]['packets'][0]
        
        if IP in pkt and IP in first_pkt:
            if pkt[IP].src == first_pkt[IP].src:
                return 0
            else:
                return 1
        return 0
    
    def extract_flows(self, pcap_file):
        """Extract flows from PCAP file"""
        logger.info(f"[1/3] Loading PCAP file: {pcap_file}")
        start_time = time.time()
        
        try:
            packets = rdpcap(pcap_file)
            logger.info(f"    Loaded {len(packets):,} packets in {time.time()-start_time:.2f}s")
        except Exception as e:
            logger.error(f"    Error loading PCAP: {e}")
            sys.exit(1)
        
        logger.info(f"[2/3] Extracting flows...")
        processed = 0
        last_update = time.time()
        
        for pkt in packets:
            flow_id, src_ip, dst_ip, src_port, dst_port = self.create_flow_id(pkt)
            if not flow_id:
                continue
            
            direction = self.determine_direction(pkt, flow_id)
            
            # Store source/destination on first packet
            if len(self.flows[flow_id]['packets']) == 0:
                self.flows[flow_id]['src_ip'] = src_ip
                self.flows[flow_id]['dst_ip'] = dst_ip
                self.flows[flow_id]['src_port'] = src_port
                self.flows[flow_id]['dst_port'] = dst_port
            
            # Store packet info
            self.flows[flow_id]['packets'].append(pkt)
            self.flows[flow_id]['timestamps'].append(float(pkt.time))
            self.flows[flow_id]['lengths'].append(len(pkt))
            self.flows[flow_id]['directions'].append(direction)
            
            # TCP-specific features
            if TCP in pkt:
                flags = {
                    'FIN': bool(pkt[TCP].flags & 0x01),
                    'SYN': bool(pkt[TCP].flags & 0x02),
                    'RST': bool(pkt[TCP].flags & 0x04),
                    'PSH': bool(pkt[TCP].flags & 0x08),
                    'ACK': bool(pkt[TCP].flags & 0x10),
                    'URG': bool(pkt[TCP].flags & 0x20)
                }
                self.flows[flow_id]['flags'].append(flags)
                self.flows[flow_id]['window_sizes'].append(pkt[TCP].window)
                
                ip_hdr_len = pkt[IP].ihl * 4
                tcp_hdr_len = pkt[TCP].dataofs * 4
                self.flows[flow_id]['header_lens'].append(ip_hdr_len + tcp_hdr_len)
            else:
                self.flows[flow_id]['flags'].append(None)
                self.flows[flow_id]['window_sizes'].append(0)
                if UDP in pkt:
                    ip_hdr_len = pkt[IP].ihl * 4
                    self.flows[flow_id]['header_lens'].append(ip_hdr_len + 8)
            
            processed += 1
            if processed % 10000 == 0 or time.time() - last_update > 2:
                logger.info(f"   Processing: {processed:,}/{len(packets):,} packets ({processed/len(packets)*100:.1f}%)")
                last_update = time.time()
        
        logger.info(f"    Extracted {len(self.flows):,} unique flows")
        return self.flows
    
    def calculate_statistics(self, values):
        """Calculate mean, std, min, max"""
        if not values:
            return 0, 0, 0, 0
        arr = np.array(values)
        return float(np.mean(arr)), float(np.std(arr)), float(np.min(arr)), float(np.max(arr))
    
    def calculate_iat(self, timestamps):
        """Calculate Inter-Arrival Times"""
        if len(timestamps) < 2:
            return [], 0, 0, 0, 0
        
        iats = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not iats:
            return [], 0, 0, 0, 0
        
        mean, std, min_iat, max_iat = self.calculate_statistics(iats)
        return iats, mean, std, min_iat, max_iat
    
    def compute_flow_features(self):
        """Compute all flow features for each flow"""
        logger.info(f"[3/3] Computing flow features...")
        
        flow_features = []
        processed = 0
        last_update = time.time()
        
        for flow_id, flow_data in self.flows.items():
            try:
                timestamps = flow_data['timestamps']
                lengths = flow_data['lengths']
                directions = flow_data['directions']
                flags = flow_data['flags']
                window_sizes = flow_data['window_sizes']
                header_lens = flow_data['header_lens']
                
                # Separate forward and backward
                fwd_lengths = [lengths[i] for i in range(len(lengths)) if directions[i] == 0]
                bwd_lengths = [lengths[i] for i in range(len(lengths)) if directions[i] == 1]
                
                fwd_timestamps = [timestamps[i] for i in range(len(timestamps)) if directions[i] == 0]
                bwd_timestamps = [timestamps[i] for i in range(len(timestamps)) if directions[i] == 1]
                
                fwd_header_lens = [header_lens[i] for i in range(len(header_lens)) if directions[i] == 0]
                bwd_header_lens = [header_lens[i] for i in range(len(header_lens)) if directions[i] == 1]
                
                # Flow duration
                flow_duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
                
                # Packet counts
                tot_fwd_pkts = len(fwd_lengths)
                tot_bwd_pkts = len(bwd_lengths)
                
                # Packet lengths
                totlen_fwd_pkts = sum(fwd_lengths) if fwd_lengths else 0
                totlen_bwd_pkts = sum(bwd_lengths) if bwd_lengths else 0
                
                fwd_pkt_len_mean, fwd_pkt_len_std, fwd_pkt_len_min, fwd_pkt_len_max = self.calculate_statistics(fwd_lengths)
                bwd_pkt_len_mean, bwd_pkt_len_std, bwd_pkt_len_min, bwd_pkt_len_max = self.calculate_statistics(bwd_lengths)
                
                # Flow rates
                flow_byts_s = (totlen_fwd_pkts + totlen_bwd_pkts) / flow_duration if flow_duration > 0 else 0
                flow_pkts_s = len(lengths) / flow_duration if flow_duration > 0 else 0
                
                # IAT
                _, flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = self.calculate_iat(timestamps)
                
                fwd_iats, fwd_iat_mean, fwd_iat_std, fwd_iat_min, fwd_iat_max = self.calculate_iat(fwd_timestamps)
                fwd_iat_tot = sum(fwd_iats) if fwd_iats else 0
                
                bwd_iats, bwd_iat_mean, bwd_iat_std, bwd_iat_min, bwd_iat_max = self.calculate_iat(bwd_timestamps)
                bwd_iat_tot = sum(bwd_iats) if bwd_iats else 0
                
                # Flags
                fwd_psh_flags = sum(1 for i, f in enumerate(flags) if f and directions[i] == 0 and f.get('PSH', False))
                bwd_psh_flags = sum(1 for i, f in enumerate(flags) if f and directions[i] == 1 and f.get('PSH', False))
                fwd_urg_flags = sum(1 for i, f in enumerate(flags) if f and directions[i] == 0 and f.get('URG', False))
                
                fin_flag_cnt = sum(1 for f in flags if f and f.get('FIN', False))
                syn_flag_cnt = sum(1 for f in flags if f and f.get('SYN', False))
                rst_flag_cnt = sum(1 for f in flags if f and f.get('RST', False))
                psh_flag_cnt = sum(1 for f in flags if f and f.get('PSH', False))
                ack_flag_cnt = sum(1 for f in flags if f and f.get('ACK', False))
                
                # Header lengths
                fwd_header_len = sum(fwd_header_lens) if fwd_header_lens else 0
                bwd_header_len = sum(bwd_header_lens) if bwd_header_lens else 0
                
                # Packet rates
                fwd_pkts_s = tot_fwd_pkts / flow_duration if flow_duration > 0 else 0
                bwd_pkts_s = tot_bwd_pkts / flow_duration if flow_duration > 0 else 0
                
                # Packet length statistics
                pkt_len_mean, pkt_len_std, pkt_len_min, pkt_len_max = self.calculate_statistics(lengths)
                pkt_len_var = pkt_len_std ** 2
                
                # Down/Up ratio
                down_up_ratio = tot_bwd_pkts / tot_fwd_pkts if tot_fwd_pkts > 0 else 0
                
                # Average sizes
                pkt_size_avg = np.mean(lengths) if lengths else 0
                fwd_seg_size_avg = np.mean(fwd_lengths) if fwd_lengths else 0
                bwd_seg_size_avg = np.mean(bwd_lengths) if bwd_lengths else 0
                
                # Bulk rates
                fwd_byts_b_avg = totlen_fwd_pkts / tot_fwd_pkts if tot_fwd_pkts > 0 else 0
                fwd_pkts_b_avg = tot_fwd_pkts / len(fwd_timestamps) if fwd_timestamps else 0
                fwd_blk_rate_avg = 0
                
                bwd_byts_b_avg = totlen_bwd_pkts / tot_bwd_pkts if tot_bwd_pkts > 0 else 0
                bwd_pkts_b_avg = tot_bwd_pkts / len(bwd_timestamps) if bwd_timestamps else 0
                bwd_blk_rate_avg = 0
                
                # Subflow
                subflow_fwd_pkts = tot_fwd_pkts
                subflow_fwd_byts = totlen_fwd_pkts
                subflow_bwd_pkts = tot_bwd_pkts
                subflow_bwd_byts = totlen_bwd_pkts
                
                # Window sizes
                init_fwd_win_byts = window_sizes[0] if window_sizes and directions[0] == 0 else 0
                init_bwd_win_byts = next((window_sizes[i] for i in range(len(window_sizes)) if directions[i] == 1), 0)
                
                # Active/Idle
                fwd_act_data_pkts = sum(1 for i, l in enumerate(fwd_lengths) if l > 0)
                fwd_seg_size_min = min(fwd_lengths) if fwd_lengths else 0
                
                active_mean = flow_iat_mean
                active_std = flow_iat_std
                active_max = flow_iat_max
                active_min = flow_iat_min
                
                idle_mean = flow_iat_mean
                idle_std = flow_iat_std
                idle_max = flow_iat_max
                idle_min = flow_iat_min
                
                # Create feature dict
                features = {
                    'flow_id': flow_id,
                    'src_ip': flow_data['src_ip'],
                    'dst_ip': flow_data['dst_ip'],
                    'src_port': flow_data['src_port'],
                    'dst_port': flow_data['dst_port'],
                    'flow_duration': flow_duration,
                    'tot_fwd_pkts': tot_fwd_pkts,
                    'tot_bwd_pkts': tot_bwd_pkts,
                    'totlen_fwd_pkts': totlen_fwd_pkts,
                    'totlen_bwd_pkts': totlen_bwd_pkts,
                    'fwd_pkt_len_max': fwd_pkt_len_max,
                    'fwd_pkt_len_min': fwd_pkt_len_min,
                    'fwd_pkt_len_mean': fwd_pkt_len_mean,
                    'fwd_pkt_len_std': fwd_pkt_len_std,
                    'bwd_pkt_len_max': bwd_pkt_len_max,
                    'bwd_pkt_len_min': bwd_pkt_len_min,
                    'bwd_pkt_len_mean': bwd_pkt_len_mean,
                    'bwd_pkt_len_std': bwd_pkt_len_std,
                    'flow_byts_s': flow_byts_s,
                    'flow_pkts_s': flow_pkts_s,
                    'flow_iat_mean': flow_iat_mean,
                    'flow_iat_std': flow_iat_std,
                    'flow_iat_max': flow_iat_max,
                    'flow_iat_min': flow_iat_min,
                    'fwd_iat_tot': fwd_iat_tot,
                    'fwd_iat_mean': fwd_iat_mean,
                    'fwd_iat_std': fwd_iat_std,
                    'fwd_iat_max': fwd_iat_max,
                    'fwd_iat_min': fwd_iat_min,
                    'bwd_iat_tot': bwd_iat_tot,
                    'bwd_iat_mean': bwd_iat_mean,
                    'bwd_iat_std': bwd_iat_std,
                    'bwd_iat_max': bwd_iat_max,
                    'bwd_iat_min': bwd_iat_min,
                    'fwd_psh_flags': fwd_psh_flags,
                    'bwd_psh_flags': bwd_psh_flags,
                    'fwd_urg_flags': fwd_urg_flags,
                    'fwd_header_len': fwd_header_len,
                    'bwd_header_len': bwd_header_len,
                    'fwd_pkts_s': fwd_pkts_s,
                    'bwd_pkts_s': bwd_pkts_s,
                    'pkt_len_min': pkt_len_min,
                    'pkt_len_max': pkt_len_max,
                    'pkt_len_mean': pkt_len_mean,
                    'pkt_len_std': pkt_len_std,
                    'pkt_len_var': pkt_len_var,
                    'fin_flag_cnt': fin_flag_cnt,
                    'syn_flag_cnt': syn_flag_cnt,
                    'rst_flag_cnt': rst_flag_cnt,
                    'psh_flag_cnt': psh_flag_cnt,
                    'ack_flag_cnt': ack_flag_cnt,
                    'down_up_ratio': down_up_ratio,
                    'pkt_size_avg': pkt_size_avg,
                    'fwd_seg_size_avg': fwd_seg_size_avg,
                    'bwd_seg_size_avg': bwd_seg_size_avg,
                    'fwd_byts_b_avg': fwd_byts_b_avg,
                    'fwd_pkts_b_avg': fwd_pkts_b_avg,
                    'fwd_blk_rate_avg': fwd_blk_rate_avg,
                    'bwd_byts_b_avg': bwd_byts_b_avg,
                    'bwd_pkts_b_avg': bwd_pkts_b_avg,
                    'bwd_blk_rate_avg': bwd_blk_rate_avg,
                    'subflow_fwd_pkts': subflow_fwd_pkts,
                    'subflow_fwd_byts': subflow_fwd_byts,
                    'subflow_bwd_pkts': subflow_bwd_pkts,
                    'subflow_bwd_byts': subflow_bwd_byts,
                    'init_fwd_win_byts': init_fwd_win_byts,
                    'init_bwd_win_byts': init_bwd_win_byts,
                    'fwd_act_data_pkts': fwd_act_data_pkts,
                    'fwd_seg_size_min': fwd_seg_size_min,
                    'active_mean': active_mean,
                    'active_std': active_std,
                    'active_max': active_max,
                    'active_min': active_min,
                    'idle_mean': idle_mean,
                    'idle_std': idle_std,
                    'idle_max': idle_max,
                    'idle_min': idle_min
                }
                
                flow_features.append(features)
                
                processed += 1
                if processed % 100 == 0 or time.time() - last_update > 2:
                    logger.info(f"   Computing: {processed:,}/{len(self.flows):,} flows ({processed/len(self.flows)*100:.1f}%)")
                    last_update = time.time()
                
            except Exception as e:
                logger.warning(f"   Warning: Error processing flow {flow_id}: {e}")
                continue
        
        logger.info(f"    Computed features for {len(flow_features):,} flows")
        return pd.DataFrame(flow_features)


def extract_flow_features(pcap_file, output_csv='flow.csv'):
    """Main function to extract flow features"""
    logger.info("=" * 80)
    logger.info("FLOW FEATURE EXTRACTOR")
    logger.info("=" * 80)
    
    start_time = time.time()
    
    extractor = FlowFeatureExtractor()
    extractor.extract_flows(pcap_file)
    flow_df = extractor.compute_flow_features()
    
    # Save
    flow_df.to_csv(output_csv, index=False)
    
    logger.info(f"{'='*80}")
    logger.info(f" Flow extraction complete in {time.time() - start_time:.2f}s")
    logger.info(f" Saved to: {output_csv}")
    logger.info(f" Total flows: {len(flow_df):,}")
    logger.info(f"{'='*80}")
    
    return flow_df


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        logger.error("Usage: python flow_extractor.py <pcap_file> [output_csv]")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_csv = sys.argv[2] if len(sys.argv) > 2 else 'flow.csv'
    
    extract_flow_features(pcap_file, output_csv)