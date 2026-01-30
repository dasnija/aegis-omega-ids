#!/usr/bin/env python3
"""
main_pipeline.py
Complete PCAP to CSV Pipeline: Flow Extraction → Payload Extraction → Merging → Inference
"""
import os
import sys
import time
import json
from pathlib import Path
import io

# Fix Windows console encoding to support Unicode characters
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Import our modules
from flow_extractor import extract_flow_features
from payload_extractor import extract_payload_features
from merger import merge_flow_payload

# ============================================================================
# MAIN PIPELINE
# ============================================================================
def run_pipeline(pcap_file, output_dir, labels_file=None, models_dir=None, skip_inference=False):
    """Run complete pipeline - Extract flows, payloads, merge, and optionally run inference
    
    Args:
        pcap_file: Path to input PCAP file
        output_dir: Directory to save output files
        labels_file: Optional path to labels JSONL file
        models_dir: Optional path to models directory
        skip_inference: If True, skip step 4 (inference) - useful when FastAPI will use in-memory models
    """
    
    # Create output directory
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Define output files
    flow_csv = output_dir / "flow.csv"
    payload_csv = output_dir / "payloads.csv"
    merged_csv = output_dir / "merged.csv"
    results_json = output_dir / "results.json"
    
    print("=" * 80, flush=True)
    print("PCAP PROCESSING PIPELINE", flush=True)
    print("=" * 80, flush=True)
    print(f"PCAP: {pcap_file}", flush=True)
    print(f"Output: {output_dir}", flush=True)
    print(f"Labels: {labels_file if labels_file else 'None'}", flush=True)
    
    if not os.path.exists(pcap_file):
        print(f"ERROR: PCAP file not found: {pcap_file}", file=sys.stderr, flush=True)
        sys.exit(1)
    
    pipeline_start = time.time()
    
    # Step 1: Extract flow features
    print(f"\n{'='*80}", flush=True)
    print("STEP 1/4: FLOW FEATURE EXTRACTION", flush=True)
    print(f"{'='*80}", flush=True)
    
    try:
        flow_df = extract_flow_features(pcap_file, str(flow_csv))
        print(f"Flow extraction complete: {len(flow_df)} flows", flush=True)
    except Exception as e:
        print(f"ERROR in flow extraction: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    
    # Step 2: Extract payload features
    print(f"\n{'='*80}", flush=True)
    print("STEP 2/4: HTTP PAYLOAD EXTRACTION", flush=True)
    print(f"{'='*80}", flush=True)
    
    try:
        if labels_file and os.path.exists(labels_file):
            payload_df = extract_payload_features(pcap_file, labels_file, str(payload_csv))
        else:
            payload_df = extract_payload_features(pcap_file, None, str(payload_csv))
        print(f"Payload extraction complete: {len(payload_df)} payloads", flush=True)
    except Exception as e:
        print(f"ERROR in payload extraction: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    
    # Step 3: Merge flow and payload features
    print(f"\n{'='*80}", flush=True)
    print("STEP 3/4: MERGING FEATURES", flush=True)
    print(f"{'='*80}", flush=True)
    
    try:
        merged_df = merge_flow_payload(str(flow_csv), str(payload_csv), str(merged_csv))
        print(f"Merge complete: {len(merged_df)} rows", flush=True)
    except Exception as e:
        print(f"ERROR in merging: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    
    # Step 4: Run inference (or skip if using in-memory models)
    if skip_inference:
        print(f"\n{'='*80}", flush=True)
        print("STEP 4/4: SKIPPING INFERENCE (will use in-memory models)", flush=True)
        print(f"{'='*80}", flush=True)
        print("CSV conversion complete. FastAPI will run inference with pre-loaded models.", flush=True)
        
        # Still need to return early with success
        total_time = time.time() - pipeline_start
        print(f"\n{'='*80}", flush=True)
        print("PIPELINE COMPLETE (Steps 1-3 only)", flush=True)
        print(f"{'='*80}", flush=True)
        print(f"\nTotal execution time: {total_time:.2f}s", flush=True)
        print(f"\nOutput files:", flush=True)
        print(f"  1. Flow features:     {flow_csv}", flush=True)
        print(f"  2. Payload features:  {payload_csv}", flush=True)
        print(f"  3. Merged CSV:        {merged_csv}", flush=True)
        print(f"\n All files ready in: {output_dir}", flush=True)
        print(f"{'='*80}\n", flush=True)
        return 0  # Success
    
    print(f"\n{'='*80}", flush=True)
    print("STEP 4/4: RUNNING MODEL INFERENCE", flush=True)
    print(f"{'='*80}", flush=True)
    
    
    try:
        # We need to import EnhancedInferencePipeline from backend/inference.py
        # NOT from backend/inference/inference.py (which has InferencePipeline)
        # Use importlib to load the specific file
        import importlib.util
        
        backend_dir = Path(__file__).resolve().parent.parent / 'backend'
        inference_module_path = backend_dir / 'inference.py'
        
        if not inference_module_path.exists():
            raise FileNotFoundError(f"Inference module not found: {inference_module_path}")
        
        print(f"Loading inference module from {inference_module_path}...", flush=True)
        
        # Load the inference.py module directly
        spec = importlib.util.spec_from_file_location("backend_inference", inference_module_path)
        backend_inference = importlib.util.module_from_spec(spec)
        
        # Also add backend/inference to path for sub-module imports (config, signature_filter, etc.)
        inference_dir = backend_dir / 'inference'
        if str(inference_dir) not in sys.path:
            sys.path.insert(0, str(inference_dir))
        
        # Execute the module to load its classes
        print("Executing inference module...", flush=True)
        spec.loader.exec_module(backend_inference)
        
        # Get the EnhancedInferencePipeline class
        EnhancedInferencePipeline = backend_inference.EnhancedInferencePipeline
        
        print("Initializing inference pipeline (loading models)...", flush=True)
        
        # Initialize pipeline
        if models_dir:
            pipeline = EnhancedInferencePipeline(models_dir=models_dir)
        else:
            pipeline = EnhancedInferencePipeline()
        
        print("Pipeline initialized! Running inference...", flush=True)
        
        # Run inference
        results, metrics = pipeline.generate_detailed_json_report(
            input_path=merged_csv,
            output_path=results_json,
            include_layer_details=True,
            include_true_labels=False
        )
        
        print(f"Inference complete: {len(results)} predictions", flush=True)
        
    except Exception as e:
        print(f"ERROR in inference: {e}", file=sys.stderr, flush=True)
        sys.exit(1)
    
    # Final summary
    print(f"\n{'='*80}", flush=True)
    print("PIPELINE COMPLETE", flush=True)
    print(f"{'='*80}", flush=True)
    
    total_time = time.time() - pipeline_start
    print(f"\nTotal execution time: {total_time:.2f}s", flush=True)
    print(f"\nOutput files:", flush=True)
    print(f"  1. Flow features:     {flow_csv}", flush=True)
    print(f"  2. Payload features:  {payload_csv}", flush=True)
    print(f"  3. Merged CSV:        {merged_csv}", flush=True)
    print(f"  4. Inference results: {results_json}", flush=True)
    
    print(f"\n All files ready in: {output_dir}", flush=True)
    print(f"{'='*80}\n", flush=True)
    
    return 0  # Success exit code

# ============================================================================
# CLI INTERFACE
# ============================================================================
def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='PCAP Processing Pipeline')
    parser.add_argument('pcap_file', help='Input PCAP file path')
    parser.add_argument('output_dir', help='Output directory for results')
    parser.add_argument('--labels', default=None, help='Optional labels JSONL file')
    parser.add_argument('--models-dir', default=None, help='Optional models directory')
    parser.add_argument('--skip-inference', action='store_true', 
                       help='Skip inference step (Steps 1-3 only, FastAPI will use in-memory models)')
    
    args = parser.parse_args()
    
    try:
        exit_code = run_pipeline(
            pcap_file=args.pcap_file,
            output_dir=args.output_dir,
            labels_file=args.labels,
            models_dir=args.models_dir,
            skip_inference=args.skip_inference
        )
        sys.exit(exit_code)
    except Exception as e:
        print(f"FATAL ERROR: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()