# System Performance Benchmarking

This directory contains scripts and tools to evaluate the performance of the Hybrid IDS inference engine. It measures latency, throughput, CPU usage, and memory consumption across different batch sizes.

## 📋 Prerequisites

-   **Python 3.9+**
-   **Dependencies**: `psutil`, `pandas` (Install via `pip install psutil pandas`)
-   **Target Files**: The benchmarking script requires:
    1.  `inference.py` (The inference engine to test)
    2.  `old.csv` (Test dataset with flow features)

## 🚀 How to Run

Since the benchmarking script depends on the backend code, you must ensure the required files are accessible.

### 1. Setup Environment
Copy the `system_benchmarking.py` script to the `backend/` directory so it can import `inference.py` and dependencies correctly.
```bash
cp benchmark/system_benchmarking.py backend/
cp benchmark/benchmark/benchmark_results_gpu.csv backend/ # Optional: for comparison
```

### 2. Prepare Test Data
Ensure a test CSV file named `old.csv` (or update the `TEST_INPUT_FILE` variable in the script) is present in the `backend/` directory.

### 3. Execute Benchmark
Run the script from the `backend/` directory:
```bash
cd backend
python system_benchmarking.py
```

## 📊 interpreting the Results

The script generates a `benchmark_results.csv` file. You can open this in Excel or Google Sheets.

### Key Metrics Explained

| Metric Column | Description | Ideal Trend |
| :--- | :--- | :--- |
| `batch_size` | Number of packets processed in one pass. | N/A |
| `latency_ms_avg` | Average time to process the **entire batch**. | Lower is better. |
| `throughput_pkt_per_sec` | Number of packets processed per second. | **Higher is better.** This is the most critical metric for scalability. |
| `cpu_percent_avg` | Average CPU utilization during the test. | Lower is better (allows room for other tasks). |
| `ram_mb_avg` | Memory usage in MB. | Lower is better. |

### Example Analysis

**1. Latency vs. Throughput**
-   **Small Batch (1)**: Low latency (e.g., 20ms) but low throughput (e.g., 50 pkts/sec). Good for real-time API.
-   **Large Batch (1000)**: High latency (e.g., 500ms) but huge throughput (e.g., 2000 pkts/sec). Good for bulk PCAP processing.

**2. GPU vs. CPU**
If comparing `benchmark_results_gpu.csv` vs. standard results:
-   **GPU** excels at large batches (100+), often showing 10x throughput gains.
-   **CPU** is often faster or comparable for single-packet inference due to lower data transfer overhead.

## 📁 Files in this Directory

-   `system_benchmarking.py`: Main automated test script.
-   `benchmark/benchmark_results.csv`: Results from standard CPU execution.
-   `benchmark/benchmark_results_gpu.csv`: Reference results from GPU-accelerated run.
-   `bench_opt.py`: Experimental script for optimized inference testing.
