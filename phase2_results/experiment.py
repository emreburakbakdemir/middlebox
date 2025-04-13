#!/usr/bin/env python3
import subprocess
import time
import statistics
import math
import argparse

def run_trial(bits, msg, timeout):
    """
    Runs a single trial:
      1. Starts the receiver in the "insec" container.
      2. Waits for the receiver to initialize.
      3. Runs the sender in the "sec" container.
      4. Waits for the receiver to exit (it exits early once the full message is received).
    Returns the elapsed time and the receiver’s output.
    """
    # Build the receiver command.
    rec_cmd = [
        "docker", "exec", "insec",
        "python3", "receiver.py",
        "--bits", str(bits),
        "--timeout", str(timeout)
    ]
    # Start the receiver process.
    rec_proc = subprocess.Popen(rec_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Give the receiver a moment to initialize.
    time.sleep(1)
    
    # Build the sender command (no delay parameter this time).
    send_cmd = [
        "docker", "exec", "sec",
        "python3", "sender.py",
        "--bits", str(bits),
        "--msg", msg
    ]
    
    start_time = time.time()
    # Run sender (blocking).
    subprocess.run(send_cmd, check=True)
    
    # Wait for the receiver process to complete.
    rec_stdout, rec_stderr = rec_proc.communicate()
    end_time = time.time()
    
    elapsed = end_time - start_time
    return elapsed, rec_stdout

def compute_capacity(elapsed, total_bits):
    """Computes channel throughput in bits per second."""
    return total_bits / elapsed

def confidence_interval(data, confidence=0.95):
    n = len(data)
    if n < 2:
        return (data[0], data[0])
    mean_val = statistics.mean(data)
    stdev = statistics.stdev(data)
    # Use an approximate t-value for our sample size (e.g., 2.131 for ~30 trials)
    t = 2.131
    margin = t * stdev / math.sqrt(n)
    return (mean_val - margin, mean_val + margin)

def main():
    parser = argparse.ArgumentParser(description="Covert Channel Experimentation Campaign")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Receiver timeout (seconds). Receiver exits early when full message is received.")
    parser.add_argument("--trials", type=int, default=10,
                        help="Number of trials for each configuration.")
    parser.add_argument("--output", type=str, default="experiment_results.txt",
                        help="Output file to store the experiment results.")
    args = parser.parse_args()
    
    # Define parameter spaces.
    bits_options = [4, 5]
    # Remove delay variations; no inter-packet delay.
    msg_options = [
        "fourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfour",
        "fourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfour",
        "fourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfourfour" #96
    ]
    
    results = []
    
    for bits in bits_options:
        for msg in msg_options:
            total_bits = 16 + len(msg) * 8  # 16-bit header + (8 bits per character)
            capacities = []
            elapsed_times = []
            print(f"\nConfiguration: bits={bits}, message='{msg}' (length: {len(msg)} bytes)")
            for trial in range(args.trials):
                print(f"  Trial {trial + 1}:")
                try:
                    elapsed, rec_output = run_trial(bits, msg, args.timeout)
                except subprocess.CalledProcessError as e:
                    print("Error in trial:", e)
                    continue
                capacity = compute_capacity(elapsed, total_bits)
                elapsed_times.append(elapsed)
                capacities.append(capacity)
                print(f"    Elapsed time: {elapsed:.4f} s, Capacity: {capacity:.2f} bits/s")
                print("    Receiver output snippet:")
                print(rec_output.strip())
            if capacities:
                avg_elapsed = statistics.mean(elapsed_times)
                avg_capacity = statistics.mean(capacities)
                ci_low, ci_high = confidence_interval(capacities)
                config_result = {
                    "bits": bits,
                    "msg": msg,
                    "msg_length": len(msg),
                    "avg_elapsed": avg_elapsed,
                    "avg_capacity": avg_capacity,
                    "ci_low": ci_low,
                    "ci_high": ci_high
                }
                results.append(config_result)
    
    with open(args.output, "w") as f:
        f.write("Covert Channel Experiment Results\n")
        f.write("=================================\n")
        for r in results:
            line = (f"bits: {r['bits']}, msg_length: {r['msg_length']} bytes, "
                    f"avg_elapsed: {r['avg_elapsed']:.4f} s, "
                    f"avg_capacity: {r['avg_capacity']:.2f} bits/s, "
                    f"95% CI: [{r['ci_low']:.2f}, {r['ci_high']:.2f}] bits/s\n")
            f.write(line)
            print(line.strip())
    
    print("\nExperimentation complete! Results saved to", args.output)

if __name__ == "__main__":
    main()
