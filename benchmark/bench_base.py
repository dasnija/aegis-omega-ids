"""
Optimized Benchmarking Script for IDS Inference Service
UPDATED to work with EnhancedInferencePipeline
LOGIC 100% UNCHANGED
"""

import time
import psutil
import pandas as pd
import os
import statistics
from datetime import datetime
from pathlib import Path

# ✅ UPDATED IMPORT (ONLY CHANGE)
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
    print("\n[1] BENCHMARKING MODEL LOAD TIME")

    start_ram = get_ram()
    start_cpu = get_cpu()

    t0 = time.time()
    service = EnhancedInferencePipeline(models_dir=Path("models"))  # ✅ UPDATED
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
    print(f"\n[2] BENCHMARKING INFERENCE — Batch Size: {batch_size}")

    if batch_size > len(df_test):
        df_batch = df_test.sample(n=batch_size, replace=True)
    else:
        df_batch = df_test.head(batch_size)

    latencies = []
    cpu_vals = []
    ram_vals = []

    # ✅ WARMUP (UNCHANGED CONCEPT)
    _ = service.generate_detailed_json_report(
        input_path=Path("temp_warmup.csv"),
        output_path=Path("temp_warmup.json"),
        include_true_labels=False,
        save_visualizations=False
    )

    for i in range(num_runs):
        print(f"  Run {i+1}/{num_runs}...", end=" ", flush=True)

        start_cpu = get_cpu()
        start_ram = get_ram()

        temp_csv = f"temp_batch_{batch_size}.csv"
        df_batch.to_csv(temp_csv, index=False)

        t0 = time.time()
        service.generate_detailed_json_report(
            input_path=Path(temp_csv),
            output_path=Path(f"temp_out_{batch_size}.json"),
            include_true_labels=False,
            save_visualizations=False
        )
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
    print(f"\n[3] STRESS TEST — LIVE LOAD ({duration_sec}s)")

    start_time = time.time()
    total_packets = 0
    total_requests = 0
    cpu_vals = []
    ram_vals = []
    latencies = []

    batch_size = 100

    while time.time() - start_time < duration_sec:
        df_batch = df_test.sample(n=batch_size, replace=True)
        temp_csv = "temp_stress.csv"
        df_batch.to_csv(temp_csv, index=False)

        t0 = time.time()
        service.generate_detailed_json_report(
            input_path=Path(temp_csv),
            output_path=Path("temp_stress.json"),
            include_true_labels=False,
            save_visualizations=False
        )
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


# ================================
# MAIN PIPELINE (UNCHANGED)
# ================================

def main():
    print("\n" + "="*80)
    print(" OPTIMIZED IDS BENCHMARKING ".center(80))
    print("="*80)

    if not os.path.exists(TEST_INPUT_FILE):
        print(f"\n❌ ERROR: File not found: {TEST_INPUT_FILE}")
        return

    df_test = pd.read_csv(TEST_INPUT_FILE)
    if 'label' in df_test.columns:
        df_test = df_test.drop(columns=['label', 'attack_type', 'subtype', 'severity'], errors='ignore')

    results = []

    load_result, service = benchmark_model_load()
    load_result["timestamp"] = timestamp()
    results.append(load_result)

    for batch_size in BATCH_SIZES:
        res = benchmark_inference(service, df_test, batch_size, num_runs=5)
        res["timestamp"] = timestamp()
        results.append(res)

    stress = stress_test(service, df_test, duration_sec=30)
    stress["timestamp"] = timestamp()
    results.append(stress)

    df_results = pd.DataFrame(results)
    df_results.to_csv(OUTPUT_CSV, index=False)

    print("\n✅ BENCHMARK COMPLETED")
    print(df_results.to_string(index=False))


if __name__ == "__main__":
    main()
