import time
import psutil
import pandas as pd
import subprocess
import os
import statistics
import tempfile
import shutil
from datetime import datetime

# ================================
# CONFIGURATION
# ================================

INFERENCE_SCRIPT = "inference.py"
TEST_INPUT_FILE = "old.csv"  # Your test packet samples
OUTPUT_CSV = "benchmark_results.csv"

BATCH_SIZES = [1, 10, 100, 500, 1000]

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
# PREPARE TEST DATA
# ================================

def prepare_batch_file(batch_size):
    """Create a temporary CSV file with the specified batch size"""
    df_full = pd.read_csv(TEST_INPUT_FILE)
    
    # Sample the desired batch size (with replacement if needed)
    if batch_size > len(df_full):
        df_batch = df_full.sample(n=batch_size, replace=True)
    else:
        df_batch = df_full.head(batch_size)
    
    # Create temporary file
    temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
    df_batch.to_csv(temp_file.name, index=False)
    temp_file.close()
    
    return temp_file.name

# ================================
# MODEL LOAD BENCHMARK
# ================================

def benchmark_model_load():
    """
    Benchmark model loading by running a minimal inference
    The first run will include model load time
    """
    print("\n[1] BENCHMARKING MODEL LOAD TIME")
    
    temp_input = prepare_batch_file(1)
    temp_output = tempfile.mktemp(suffix='.csv')
    
    print(f"  Using temp input: {temp_input}")
    print(f"  Using temp output: {temp_output}")
    
    start_ram = get_ram()
    start_cpu = get_cpu()
    
    t0 = time.time()
    
    result = subprocess.run([
        "python", INFERENCE_SCRIPT,
        "--input", temp_input,
        "--output", temp_output,
        "--no-visualizations"
    ], capture_output=True, text=True)
    
    load_time = time.time() - t0
    
    end_cpu = get_cpu()
    end_ram = get_ram()
    
    # Show output for debugging
    if result.returncode != 0:
        print(f"\n❌ Model load test FAILED (exit code {result.returncode})")
        print("\n--- STDOUT ---")
        print(result.stdout)
        print("\n--- STDERR ---")
        print(result.stderr)
        print("--- END ---\n")
    else:
        print(f"ok Model load successful ({load_time:.2f}s)")
    
    # Cleanup
    try:
        os.unlink(temp_input)
    except:
        pass
    
    if os.path.exists(temp_output):
        try:
            os.unlink(temp_output)
        except:
            pass
    
    return {
        "test_type": "model_load",
        "batch_size": 1,
        "latency_ms": load_time * 1000,
        "cpu_percent": end_cpu - start_cpu,
        "ram_mb": end_ram - start_ram,
        "throughput_pkt_per_sec": "N/A",
        "status": "success" if result.returncode == 0 else "failed"
    }

# ================================
# INFERENCE BENCHMARK
# ================================

def benchmark_inference(batch_size, num_runs=5):
    print(f"\n[2] BENCHMARKING INFERENCE — Batch Size: {batch_size}")
    
    latencies = []
    cpu_vals = []
    ram_vals = []
    
    for i in range(num_runs):
        print(f"  Run {i+1}/{num_runs}...", end=" ", flush=True)
        
        temp_input = prepare_batch_file(batch_size)
        temp_output = tempfile.mktemp(suffix='.csv')
        
        start_cpu = get_cpu()
        start_ram = get_ram()
        
        t0 = time.time()
        
        result = subprocess.run([
            "python", INFERENCE_SCRIPT,
            "--input", temp_input,
            "--output", temp_output,
            "--no-visualizations"
        ], capture_output=True, text=True)
        
        latency = (time.time() - t0) * 1000
        
        end_cpu = get_cpu()
        end_ram = get_ram()
        
        # Cleanup
        try:
            os.unlink(temp_input)
        except:
            pass
        
        if os.path.exists(temp_output):
            try:
                os.unlink(temp_output)
            except:
                pass
        
        if result.returncode == 0:
            latencies.append(latency)
            cpu_vals.append(end_cpu - start_cpu)
            ram_vals.append(end_ram)
            print(f"{latency:.2f}ms ✓")
        else:
            print(f"FAILED (exit code {result.returncode})")
            
            # Show error details only for first failure
            if i == 0:
                print(f"\n  ⚠️  Error details for batch size {batch_size}:")
                print(f"  --- STDOUT ---")
                if result.stdout.strip():
                    print("  " + result.stdout.strip().replace("\n", "\n  "))
                else:
                    print("  (empty)")
                print(f"  --- STDERR ---")
                if result.stderr.strip():
                    print("  " + result.stderr.strip().replace("\n", "\n  "))
                else:
                    print("  (empty)")
                print(f"  --- END ---\n")
    
    if not latencies:
        print(f"  ❌ All runs failed for batch size {batch_size}")
        return None
    
    throughput = batch_size / (statistics.mean(latencies) / 1000)
    
    return {
        "test_type": "inference",
        "batch_size": batch_size,
        "latency_ms_avg": statistics.mean(latencies),
        "latency_ms_p95": sorted(latencies)[int(0.95 * len(latencies))],
        "latency_ms_max": max(latencies),
        "cpu_percent_avg": statistics.mean(cpu_vals),
        "ram_mb_avg": statistics.mean(ram_vals),
        "throughput_pkt_per_sec": throughput,
        "successful_runs": len(latencies),
        "total_runs": num_runs
    }

# ================================
# LIVE STRESS TEST
# ================================

def stress_test(duration_sec=60):
    print(f"\n[3] STRESS TEST — LIVE LOAD ({duration_sec}s)")
    
    start_time = time.time()
    total_requests = 0
    failed_requests = 0
    cpu_vals = []
    ram_vals = []
    latencies = []
    
    while time.time() - start_time < duration_sec:
        temp_input = prepare_batch_file(1)
        temp_output = tempfile.mktemp(suffix='.csv')
        
        cpu_before = get_cpu()
        ram_before = get_ram()
        
        t0 = time.time()
        
        result = subprocess.run([
            "python", INFERENCE_SCRIPT,
            "--input", temp_input,
            "--output", temp_output,
            "--no-visualizations"
        ], capture_output=True, text=True)
        
        latency = (time.time() - t0) * 1000
        
        # Cleanup
        try:
            os.unlink(temp_input)
        except:
            pass
        
        if os.path.exists(temp_output):
            try:
                os.unlink(temp_output)
            except:
                pass
        
        if result.returncode == 0:
            total_requests += 1
            latencies.append(latency)
            cpu_vals.append(get_cpu())
            ram_vals.append(get_ram())
        else:
            failed_requests += 1
            # Show first error
            if failed_requests == 1:
                print(f"\n  ⚠️  Stress test inference error:")
                print(f"  STDERR: {result.stderr[:200]}")
        
        elapsed = time.time() - start_time
        if (total_requests + failed_requests) % 10 == 0:
            print(f"  {elapsed:.1f}s elapsed, {total_requests} successful, {failed_requests} failed")
    
    actual_duration = time.time() - start_time
    throughput = total_requests / actual_duration
    
    print(f"\n  Summary: {total_requests} successful, {failed_requests} failed in {actual_duration:.1f}s")
    
    return {
        "test_type": "stress_test",
        "batch_size": "1 (continuous)",
        "latency_ms_avg": statistics.mean(latencies) if latencies else "N/A",
        "latency_ms_p95": sorted(latencies)[int(0.95 * len(latencies))] if latencies else "N/A",
        "latency_ms_max": max(latencies) if latencies else "N/A",
        "cpu_percent_avg": statistics.mean(cpu_vals) if cpu_vals else "N/A",
        "ram_mb_avg": statistics.mean(ram_vals) if ram_vals else "N/A",
        "throughput_pkt_per_sec": throughput,
        "successful_requests": total_requests,
        "failed_requests": failed_requests
    }

# ================================
# MAIN BENCHMARK PIPELINE
# ================================

def main():
    print("\n" + "="*80)
    print(" IDS SYSTEM RESOURCE BENCHMARKING ".center(80))
    print("="*80)
    print(f"Test input file: {TEST_INPUT_FILE}")
    print(f"Inference script: {INFERENCE_SCRIPT}")
    print(f"Batch sizes to test: {BATCH_SIZES}")
    
    # Verify files exist
    if not os.path.exists(TEST_INPUT_FILE):
        print(f"\n❌ ERROR: Test input file not found: {TEST_INPUT_FILE}")
        return
    
    if not os.path.exists(INFERENCE_SCRIPT):
        print(f"\n❌ ERROR: Inference script not found: {INFERENCE_SCRIPT}")
        return
    
    # Check test data
    df_test = pd.read_csv(TEST_INPUT_FILE)
    print(f"Test data: {len(df_test)} rows, {len(df_test.columns)} columns")
    print("="*80)
    
    results = []
    
    # 1. Model Load Test
    try:
        load_result = benchmark_model_load()
        load_result["timestamp"] = timestamp()
        results.append(load_result)
    except Exception as e:
        print(f"❌ Model load benchmark failed with exception: {e}")
        import traceback
        traceback.print_exc()
    
    # 2. Inference Tests
    for b in BATCH_SIZES:
        try:
            res = benchmark_inference(b, num_runs=5)
            if res:
                res["timestamp"] = timestamp()
                results.append(res)
        except Exception as e:
            print(f"❌ Inference benchmark (batch={b}) failed with exception: {e}")
            import traceback
            traceback.print_exc()
    
    # 3. Stress Test (optional - comment out if too long)
    try:
        stress = stress_test(duration_sec=30)
        stress["timestamp"] = timestamp()
        results.append(stress)
    except Exception as e:
        print(f"❌ Stress test failed with exception: {e}")
        import traceback
        traceback.print_exc()
    
    # Save results
    if results:
        df = pd.DataFrame(results)
        df.to_csv(OUTPUT_CSV, index=False)
        
        print("\n" + "="*80)
        print(" BENCHMARK COMPLETED ".center(80))
        print("="*80)
        print(f"Results saved to: {OUTPUT_CSV}")
        print("\n" + "="*80)
        print(df.to_string(index=False))
        print("="*80)
    else:
        print("\n❌ No benchmark results collected")

# ================================
# ENTRY POINT
# ================================

if __name__ == "__main__":
    main()