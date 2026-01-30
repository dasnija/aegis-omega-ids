"""
GPU-Optimized Benchmarking Script for IDS Inference Service

Compares OLD (subprocess) vs CPU-OPTIMIZED vs GPU-OPTIMIZED performance
"""

import time
import psutil
import pandas as pd
import os
import statistics
from datetime import datetime
from pathlib import Path

# Import the GPU-optimized service (NEW)
from inf_gpu2 import GPUOptimizedInferenceService

# ================================
# CONFIGURATION
# ================================

TEST_INPUT_FILE = "./data/TRAIN_READY_DATASET.csv"
OUTPUT_CSV = "benchmark_results_gpu.csv"

# LARGE BATCH SIZES - Test where GPU might shine
BATCH_SIZES = [100, 500, 1000, 5000, 10000, 20000, 50000, 100000]

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
    print("\n[1] BENCHMARKING MODEL LOAD TIME (GPU)")
    
    start_ram = get_ram()
    start_cpu = get_cpu()
    
    t0 = time.time()
    service = GPUOptimizedInferenceService(models_dir=Path("models"))
    load_time = time.time() - t0
    
    end_cpu = get_cpu()
    end_ram = get_ram()
    
    print(f"  ✓ Models loaded in {load_time:.2f}s")
    print(f"  ✓ RAM used: {end_ram - start_ram:.2f} MB")
    
    if service.gpu_available:
        print(f"  ✓ GPU: ENABLED ⚡")
    else:
        print(f"  ⚠️ GPU: NOT AVAILABLE (running on CPU)")
    
    return {
        "test_type": "model_load",
        "batch_size": 0,
        "latency_ms": load_time * 1000,
        "cpu_percent": end_cpu - start_cpu,
        "ram_mb": end_ram - start_ram,
        "throughput_pkt_per_sec": "N/A",
        "gpu_enabled": service.gpu_available
    }, service

def benchmark_inference(service, df_test, batch_size, num_runs=3):
    """Benchmark inference with pre-loaded models"""
    device = "GPU" if service.gpu_available else "CPU"
    print(f"\n[2] BENCHMARKING INFERENCE ({device}) — Batch Size: {batch_size:,}")
    
    # Prepare batch - sample with replacement if needed
    if batch_size > len(df_test):
        print(f"  📝 Note: Sampling {batch_size:,} from {len(df_test):,} rows (with replacement)")
        df_batch = df_test.sample(n=batch_size, replace=True, random_state=42)
    else:
        df_batch = df_test.head(batch_size)
    
    latencies = []
    cpu_vals = []
    ram_vals = []
    
    # Warmup run (not counted) - important for GPU!
    print(f"  Warmup run...", end=" ", flush=True)
    try:
        _ = service.predict_batch(df_batch.copy(), verbose=False)
        print("✓")
    except Exception as e:
        print(f"FAILED: {e}")
        return None
    
    # Reduce runs for very large batches to save time
    if batch_size >= 50000:
        num_runs = 2
        print(f"  ⚠️ Large batch: Running only {num_runs} iterations")
    
    for i in range(num_runs):
        print(f"  Run {i+1}/{num_runs}...", end=" ", flush=True)
        
        start_cpu = get_cpu()
        start_ram = get_ram()
        
        t0 = time.time()
        try:
            results = service.predict_batch(df_batch.copy(), verbose=False)
            latency = (time.time() - t0) * 1000
            
            end_cpu = get_cpu()
            end_ram = get_ram()
            
            latencies.append(latency)
            cpu_vals.append(end_cpu - start_cpu)
            ram_vals.append(end_ram)
            
            # Show ms for small batches, seconds for large batches
            if latency > 10000:
                print(f"{latency/1000:.2f}s ✓")
            else:
                print(f"{latency:.2f}ms ✓")
        except Exception as e:
            print(f"FAILED: {e}")
            continue
    
    if not latencies:
        print(f"  ❌ All runs failed for batch size {batch_size}")
        return None
    
    throughput = batch_size / (statistics.mean(latencies) / 1000)
    
    return {
        "test_type": "inference",
        "batch_size": batch_size,
        "latency_ms_avg": statistics.mean(latencies),
        "latency_ms_p95": sorted(latencies)[int(0.95 * len(latencies))] if len(latencies) > 1 else latencies[0],
        "latency_ms_max": max(latencies),
        "latency_ms_min": min(latencies),
        "cpu_percent_avg": statistics.mean(cpu_vals),
        "ram_mb_avg": statistics.mean(ram_vals),
        "throughput_pkt_per_sec": throughput,
        "gpu_enabled": service.gpu_available
    }

def stress_test(service, df_test, duration_sec=60):
    """Stress test with continuous predictions - longer duration for large batches"""
    device = "GPU" if service.gpu_available else "CPU"
    print(f"\n[3] STRESS TEST ({device}) — LIVE LOAD ({duration_sec}s)")
    
    start_time = time.time()
    total_packets = 0
    total_requests = 0
    cpu_vals = []
    ram_vals = []
    latencies = []
    
    # Use larger batches to test GPU advantage
    batch_size = 500
    print(f"  Using batch size: {batch_size}")
    
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
        
        if total_requests % 20 == 0:
            elapsed = time.time() - start_time
            current_throughput = total_packets / elapsed
            print(f"  {elapsed:.1f}s: {total_packets:,} packets, {current_throughput:.1f} pkt/s")
    
    actual_duration = time.time() - start_time
    throughput = total_packets / actual_duration
    
    print(f"\n  Summary: {total_packets:,} packets in {actual_duration:.1f}s")
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
        "total_requests": total_requests,
        "gpu_enabled": service.gpu_available
    }

def compare_with_previous_results():
    """Load and compare with previous benchmark results"""
    comparisons = []
    
    # Check for old subprocess results
    old_csv = "benchmark_results.csv"
    if os.path.exists(old_csv):
        old_df = pd.read_csv(old_csv)
        old_1000 = old_df[(old_df['test_type'] == 'inference') & 
                          (old_df['batch_size'] == 1000)]
        if not old_1000.empty:
            comparisons.append({
                'name': 'OLD (subprocess)',
                'latency': old_1000['latency_ms_avg'].values[0],
                'throughput': old_1000['throughput_pkt_per_sec'].values[0]
            })
    
    # Check for CPU-optimized results
    cpu_csv = "benchmark_results_optimized.csv"
    if os.path.exists(cpu_csv):
        cpu_df = pd.read_csv(cpu_csv)
        cpu_1000 = cpu_df[(cpu_df['test_type'] == 'inference') & 
                          (cpu_df['batch_size'] == 1000)]
        if not cpu_1000.empty:
            comparisons.append({
                'name': 'CPU-OPTIMIZED',
                'latency': cpu_1000['latency_ms_avg'].values[0],
                'throughput': cpu_1000['throughput_pkt_per_sec'].values[0]
            })
    
    return comparisons

# ================================
# MAIN BENCHMARK PIPELINE
# ================================

def main():
    print("\n" + "="*80)
    print(" GPU vs CPU LARGE BATCH BENCHMARKING ".center(80))
    print(" (Testing 10K, 20K, 50K, 100K batches) ".center(80))
    print("="*80)
    print(f"Test input file: {TEST_INPUT_FILE}")
    print(f"Batch sizes to test: {[f'{b:,}' for b in BATCH_SIZES]}")
    print(f"\n💡 Large batches show GPU advantage better!")
    
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
    
    print(f"✓ Loaded {len(df_test):,} rows, {len(df_test.columns)} columns")
    print("="*80)
    
    results = []
    
    # 1. Model Load Test (ONE TIME ONLY!)
    try:
        load_result, service = benchmark_model_load()
        load_result["timestamp"] = timestamp()
        results.append(load_result)
        
        print(f"\n🎉 Models loaded and ready!")
        if service.gpu_available:
            print(f"   ⚡ GPU ACCELERATION: ENABLED")
            print(f"   🚀 Large batches should show GPU advantage!")
        else:
            print(f"   ⚠️ GPU NOT DETECTED - running on CPU")
        print(f"   From now on: NO MORE MODEL LOADING!")
        
    except Exception as e:
        print(f"❌ Model load failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # 2. Inference Tests (using SAME loaded models)
    print("\n" + "="*80)
    device = "GPU" if service.gpu_available else "CPU"
    print(f" LARGE BATCH INFERENCE BENCHMARKS ({device}) ".center(80))
    print("="*80)
    
    successful_tests = 0
    failed_tests = 0
    
    for batch_size in BATCH_SIZES:
        try:
            res = benchmark_inference(service, df_test, batch_size)
            if res is not None:
                res["timestamp"] = timestamp()
                results.append(res)
                successful_tests += 1
                
                # Show progress
                throughput = res['throughput_pkt_per_sec']
                latency = res['latency_ms_avg']
                if latency > 10000:
                    print(f"  ✓ {batch_size:>6,} packets: {latency/1000:>6.2f}s → {throughput:>8,.0f} pkt/s")
                else:
                    print(f"  ✓ {batch_size:>6,} packets: {latency:>6.2f}ms → {throughput:>8,.0f} pkt/s")
            else:
                failed_tests += 1
                print(f"  ✗ {batch_size:>6,} packets: FAILED")
        except Exception as e:
            failed_tests += 1
            print(f"  ✗ {batch_size:>6,} packets: ERROR - {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n  Summary: {successful_tests} succeeded, {failed_tests} failed")
    
    # 3. Stress Test
    try:
        print("\n" + "="*80)
        print(" STRESS TEST (60 seconds) ".center(80))
        print("="*80)
        stress = stress_test(service, df_test, duration_sec=60)
        stress["timestamp"] = timestamp()
        results.append(stress)
    except Exception as e:
        print(f"❌ Stress test failed: {e}")
        import traceback
        traceback.print_exc()
    
    # Save results
    if not results:
        print("\n❌ No results to save!")
        return
    
    df_results = pd.DataFrame(results)
    df_results.to_csv(OUTPUT_CSV, index=False)
    
    print("\n" + "="*80)
    print(" BENCHMARK COMPLETED ".center(80))
    print("="*80)
    print(f"Results saved to: {OUTPUT_CSV}")
    print("\n" + "="*80)
    print(df_results.to_string(index=False))
    print("="*80)
    
    # Compare with previous results
    comparisons = compare_with_previous_results()
    
    if comparisons and not df_results[df_results['test_type'] == 'inference'].empty:
        print(f"\n" + "="*80)
        print(" PERFORMANCE COMPARISON ".center(80))
        print("="*80)
        
        inference_results = df_results[df_results['test_type'] == 'inference']
        gpu_used = service.gpu_available
        
        device_label = "GPU-ACCELERATED" if gpu_used else "CPU-OPTIMIZED"
        print(f"\n📊 {device_label} SYSTEM (this run):")
        print(f"   Batch sizes tested: {len(inference_results)}")
        print(f"   Peak throughput: {inference_results['throughput_pkt_per_sec'].max():.1f} pkt/s")
        print(f"   Best batch size: {inference_results.loc[inference_results['throughput_pkt_per_sec'].idxmax(), 'batch_size']:,}")
        
        # Show throughput scaling
        print(f"\n📈 THROUGHPUT SCALING:")
        for _, row in inference_results.iterrows():
            batch = row['batch_size']
            throughput = row['throughput_pkt_per_sec']
            latency = row['latency_ms_avg']
            if latency > 10000:
                print(f"   {batch:>6,} packets → {throughput:>8,.0f} pkt/s ({latency/1000:.2f}s)")
            else:
                print(f"   {batch:>6,} packets → {throughput:>8,.0f} pkt/s ({latency:.0f}ms)")
        
        # Compare with CPU-optimized at batch 1000
        for comp in comparisons:
            if comp['name'] == 'CPU-OPTIMIZED':
                result_1000 = inference_results[inference_results['batch_size'] == 1000]
                if not result_1000.empty:
                    new_throughput = result_1000['throughput_pkt_per_sec'].values[0]
                    speedup = new_throughput / comp['throughput']
                    
                    print(f"\n🔄 vs {comp['name']} (batch 1000):")
                    print(f"   Old: {comp['throughput']:.1f} pkt/s")
                    print(f"   New: {new_throughput:.1f} pkt/s")
                    if speedup > 1.1:
                        print(f"   🚀 {speedup:.1f}x FASTER with GPU!")
                    elif speedup < 0.9:
                        print(f"   ⚠️ {1/speedup:.1f}x SLOWER (GPU overhead)")
                    else:
                        print(f"   ≈ Same speed (±10%)")
        
        print(f"\n💡 REAL-WORLD CAPACITY:")
        max_throughput = inference_results['throughput_pkt_per_sec'].max()
        print(f"   Peak: {max_throughput:.1f} pkt/s")
        print(f"   Per hour: {max_throughput*3600:,.0f} packets")
        print(f"   Per day: {max_throughput*3600*24/1e6:.1f} MILLION packets")
        
        if gpu_used:
            print(f"\n⚡ GPU STATUS:")
            print(f"   ✓ Autoencoder: Running on GPU")
            print(f"   ✓ BiLSTM: Running on GPU with CuDNN")
            
            # Analyze if GPU helped
            if len(inference_results) >= 2:
                small_batch = inference_results.iloc[0]['throughput_pkt_per_sec']
                large_batch = inference_results.iloc[-1]['throughput_pkt_per_sec']
                scaling = large_batch / small_batch
                
                if scaling > 2:
                    print(f"   🚀 GPU shows {scaling:.1f}x scaling with larger batches!")
                else:
                    print(f"   ⚠️ Limited GPU benefit (only {scaling:.1f}x scaling)")
                    print(f"   💡 CPU might be better for your use case")
        
        print("="*80)

if __name__ == "__main__":
    main()