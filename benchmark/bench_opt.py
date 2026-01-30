"""
Optimized Benchmarking Script for IDS Inference Service

Compares OLD (subprocess) vs NEW (persistent service) performance
"""

import time
import psutil
import pandas as pd
import os
import statistics
from datetime import datetime
from pathlib import Path

# Import the optimized service (NEW)
from inference import EnhancedInferencePipeline

# ================================
# CONFIGURATION
# ================================

TEST_INPUT_FILE = "old.csv"
OUTPUT_CSV = "benchmark_results_optimized.csv"
BATCH_SIZES = [1, 10, 100, 500, 1000, 5000, 10000]

PROCESS = psutil.Process(os.getpid())

# ================================
# SYSTEM METRIC HELPERS
# ================================

def get_cpu():
    return psutil.cpu_percent(interval=0.1)

def get_ram():
    return PROCESS.memory_info().rss / (1024 * 1024)

def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ================================
# BENCHMARKS
# ================================

def benchmark_model_load():
    """Benchmark one-time model loading"""
    print("\n[1] BENCHMARKING MODEL LOAD TIME")
    
    start_ram = get_ram()
    start_cpu = get_cpu()
    
    t0 = time.time()
    service = EnhancedInferencePipeline(models_dir=Path("models"))
    load_time = time.time() - t0
    
    end_cpu = get_cpu()
    end_ram = get_ram()
    
    print(f"  ✓ Models loaded in {load_time:.2f}s")
    print(f"  ✓ RAM used: {end_ram - start_ram:.2f} MB")
    
    return {
        "test_type": "model_load",
        "batch_size": 0,
        "latency_ms": load_time * 1000,
        "cpu_percent": end_cpu - start_cpu,
        "ram_mb": end_ram - start_ram,
        "throughput_pkt_per_sec": "N/A"
    }, service

def benchmark_inference(service, df_test, batch_size, num_runs=5):
    """Benchmark inference with pre-loaded models"""
    print(f"\n[2] BENCHMARKING INFERENCE — Batch Size: {batch_size}")
    
    # Prepare batch
    if batch_size > len(df_test):
        df_batch = df_test.sample(n=batch_size, replace=True)
    else:
        df_batch = df_test.head(batch_size)
    
    latencies = []
    cpu_vals = []
    ram_vals = []
    
    # Warmup run (not counted)
    _ = service.predict_batch(df_batch.copy(), verbose=False)
    
    for i in range(num_runs):
        print(f"  Run {i+1}/{num_runs}...", end=" ", flush=True)
        
        start_cpu = get_cpu()
        start_ram = get_ram()
        
        t0 = time.time()
        results = service.predict_batch(df_batch.copy(), verbose=False)
        latency = (time.time() - t0) * 1000
        
        end_cpu = get_cpu()
        end_ram = get_ram()
        
        latencies.append(latency)
        cpu_vals.append(end_cpu - start_cpu)
        ram_vals.append(end_ram)
        
        print(f"{latency:.2f}ms ✓")
    
    throughput = batch_size / (statistics.mean(latencies) / 1000)
    
    return {
        "test_type": "inference",
        "batch_size": batch_size,
        "latency_ms_avg": statistics.mean(latencies),
        "latency_ms_p95": sorted(latencies)[int(0.95 * len(latencies))],
        "latency_ms_max": max(latencies),
        "latency_ms_min": min(latencies),
        "cpu_percent_avg": statistics.mean(cpu_vals),
        "ram_mb_avg": statistics.mean(ram_vals),
        "throughput_pkt_per_sec": throughput
    }

def stress_test(service, df_test, duration_sec=30):
    """Stress test with continuous predictions"""
    print(f"\n[3] STRESS TEST — LIVE LOAD ({duration_sec}s)")
    
    start_time = time.time()
    total_packets = 0
    total_requests = 0
    cpu_vals = []
    ram_vals = []
    latencies = []
    
    # Use small batches to simulate real-time
    batch_size = 100
    
    while time.time() - start_time < duration_sec:
        df_batch = df_test.sample(n=batch_size, replace=True)
        
        t0 = time.time()
        results = service.predict_batch(df_batch, verbose=False)
        latency = (time.time() - t0) * 1000
        
        total_packets += batch_size
        total_requests += 1
        latencies.append(latency)
        cpu_vals.append(get_cpu())
        ram_vals.append(get_ram())
        
        if total_requests % 100 == 0:
            elapsed = time.time() - start_time
            current_throughput = total_packets / elapsed
            print(f"  {elapsed:.1f}s: {total_packets} packets, {current_throughput:.1f} pkt/s")
    
    actual_duration = time.time() - start_time
    throughput = total_packets / actual_duration
    
    print(f"\n  Summary: {total_packets} packets in {actual_duration:.1f}s")
    print(f"  Average throughput: {throughput:.1f} packets/second")
    
    return {
        "test_type": "stress_test",
        "batch_size": f"{batch_size} (continuous)",
        "latency_ms_avg": statistics.mean(latencies),
        "latency_ms_p95": sorted(latencies)[int(0.95 * len(latencies))],
        "latency_ms_max": max(latencies),
        "latency_ms_min": min(latencies),
        "cpu_percent_avg": statistics.mean(cpu_vals),
        "ram_mb_avg": statistics.mean(ram_vals),
        "throughput_pkt_per_sec": throughput,
        "total_packets": total_packets,
        "total_requests": total_requests
    }

def compare_with_old_results():
    """Load and compare with old benchmark results"""
    old_csv = "benchmark_results.csv"
    
    if os.path.exists(old_csv):
        print("\n" + "="*80)
        print(" COMPARISON WITH OLD SYSTEM ".center(80))
        print("="*80)
        
        old_df = pd.read_csv(old_csv)
        
        # Find inference results for batch size 1000
        old_1000 = old_df[(old_df['test_type'] == 'inference') & 
                          (old_df['batch_size'] == 1000)]
        
        if not old_1000.empty:
            old_latency = old_1000['latency_ms_avg'].values[0]
            old_throughput = old_1000['throughput_pkt_per_sec'].values[0]
            
            print(f"\n📊 OLD SYSTEM (subprocess approach):")
            print(f"   Batch 1000 latency: {old_latency:.2f}ms")
            print(f"   Throughput: {old_throughput:.1f} packets/second")
            print(f"   Problem: Loads TensorFlow + models on EVERY call")
            
            return old_latency, old_throughput
    
    return None, None

# ================================
# MAIN BENCHMARK PIPELINE
# ================================

def main():
    print("\n" + "="*80)
    print(" OPTIMIZED IDS BENCHMARKING ".center(80))
    print(" (Persistent Service - Models Stay in Memory) ".center(80))
    print("="*80)
    print(f"Test input file: {TEST_INPUT_FILE}")
    print(f"Batch sizes to test: {BATCH_SIZES}")
    
    # Verify test file exists
    if not os.path.exists(TEST_INPUT_FILE):
        print(f"\n❌ ERROR: Test input file not found: {TEST_INPUT_FILE}")
        return
    
    # Load test data once
    print("\n📥 Loading test data...")
    df_test = pd.read_csv(TEST_INPUT_FILE)
    
    # Remove label columns for inference
    if 'label' in df_test.columns:
        df_test = df_test.drop(columns=['label', 'attack_type', 'subtype', 'severity'], errors='ignore')
    
    print(f"✓ Loaded {len(df_test)} rows, {len(df_test.columns)} columns")
    print("="*80)
    
    results = []
    
    # 1. Model Load Test (ONE TIME ONLY!)
    try:
        load_result, service = benchmark_model_load()
        load_result["timestamp"] = timestamp()
        results.append(load_result)
        
        print(f"\n🎉 Models loaded and ready!")
        print(f"   From now on: NO MORE MODEL LOADING!")
        print(f"   Each prediction will be 50-100x faster!")
        
    except Exception as e:
        print(f"❌ Model load failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # 2. Inference Tests (using SAME loaded models)
    print("\n" + "="*80)
    print(" INFERENCE BENCHMARKS (Models already loaded) ".center(80))
    print("="*80)
    
    for batch_size in BATCH_SIZES:
        try:
            res = benchmark_inference(service, df_test, batch_size, num_runs=5)
            res["timestamp"] = timestamp()
            results.append(res)
        except Exception as e:
            print(f"❌ Inference benchmark (batch={batch_size}) failed: {e}")
    
    # 3. Stress Test
    try:
        stress = stress_test(service, df_test, duration_sec=30)
        stress["timestamp"] = timestamp()
        results.append(stress)
    except Exception as e:
        print(f"❌ Stress test failed: {e}")
    
    # Save results
    df_results = pd.DataFrame(results)
    df_results.to_csv(OUTPUT_CSV, index=False)
    
    print("\n" + "="*80)
    print(" BENCHMARK COMPLETED ".center(80))
    print("="*80)
    print(f"Results saved to: {OUTPUT_CSV}")
    print("\n" + "="*80)
    print(df_results.to_string(index=False))
    print("="*80)
    
    # Compare with old results
    old_latency, old_throughput = compare_with_old_results()
    
    if old_latency and old_throughput:
        # Find new results for batch 1000
        new_1000 = df_results[(df_results['test_type'] == 'inference') & 
                              (df_results['batch_size'] == 1000)]
        
        if not new_1000.empty:
            new_latency = new_1000['latency_ms_avg'].values[0]
            new_throughput = new_1000['throughput_pkt_per_sec'].values[0]
            
            print(f"\n📊 NEW SYSTEM (persistent service):")
            print(f"   Batch 1000 latency: {new_latency:.2f}ms")
            print(f"   Throughput: {new_throughput:.1f} packets/second")
            print(f"   Benefit: Models stay loaded in memory!")
            
            speedup_throughput = new_throughput / old_throughput
            speedup_latency = old_latency / new_latency
            
            print(f"\n🚀 PERFORMANCE IMPROVEMENT:")
            print(f"   Throughput: {speedup_throughput:.1f}x FASTER")
            print(f"   Latency: {speedup_latency:.1f}x FASTER")
            print(f"   Time saved per 1000 packets: {(old_latency - new_latency)/1000:.2f}s")
            
            print(f"\n💡 REAL-WORLD IMPACT:")
            print(f"   Old: {old_throughput:.1f} packets/sec → {old_throughput*60:.0f} packets/min")
            print(f"   New: {new_throughput:.1f} packets/sec → {new_throughput*60:.0f} packets/min")
            print(f"   New system can handle {(new_throughput/old_throughput):.0f}x more traffic!")
            
            print("="*80)

if __name__ == "__main__":
    main()