import matplotlib.pyplot as plt

# Given data
mean_delay = [
    "0", "0.01ms", "0.05ms", "0.1ms", "0.2ms", "0.5ms", "1ms", "2ms", 
    "3ms", "4ms", "5ms", "6ms", "7ms", "8ms", "9ms", "10ms"
]
avg_rtt = [
    1.495, 2.241, 1.915, 2.293, 2.347, 2.296, 2.002, 2.375, 
    3.285, 4.755, 4.653, 5.556, 6.161, 8.664, 8.741, 9.688
]

# Create the plot
# Create the plot with diagonal x-axis labels
plt.figure(figsize=(10, 6))
plt.plot(mean_delay, avg_rtt, marker='o', linestyle='-', color='blue')
plt.title("Average RTT vs Mean Delay")
plt.xlabel("Mean Delay (ms)")
plt.ylabel("Average RTT (ms)")
plt.xticks(rotation=20)  # Make x-axis labels diagonal
plt.grid(True)
plt.savefig("average_rtt_vs_mean_delay.png")

