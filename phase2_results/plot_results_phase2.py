import matplotlib.pyplot as plt
import numpy as np

# Data for 4-bit encoding (original + new data)
msg_lengths_4bit = [4, 8, 12, 16, 20, 24, 28, 32, 64, 96, 128]
capacities_4bit = [36.57, 48.85, 54.28, 58.16, 61.65, 65.22, 69.23, 72.94, 77.02, 83.23, 83.17]
ci_low_4bit = [35.02, 45.56, 52.44, 56.73, 59.39, 63.02, 66.97, 70.14, 75.40, 80.29, 80.50]
ci_high_4bit = [38.12, 52.13, 56.12, 59.60, 63.91, 67.43, 71.49, 75.74, 78.63, 86.16, 85.83]

# Calculate error bar values for 4-bit
errors_low_4bit = [capacities_4bit[i] - ci_low_4bit[i] for i in range(len(capacities_4bit))]
errors_high_4bit = [ci_high_4bit[i] - capacities_4bit[i] for i in range(len(capacities_4bit))]
errors_4bit = [errors_low_4bit, errors_high_4bit]

# Data for 5-bit encoding (original + new data)
msg_lengths_5bit = [4, 8, 12, 16, 20, 24, 28, 32, 64, 96, 128]
capacities_5bit = [40.22, 55.12, 62.61, 69.75, 69.97, 73.93, 80.87, 85.05, 97.74, 97.59, 101.46]
ci_low_5bit = [39.29, 53.27, 60.73, 65.58, 64.68, 70.28, 78.10, 82.65, 94.75, 94.92, 97.92]
ci_high_5bit = [41.15, 56.97, 64.50, 73.92, 75.27, 77.58, 83.64, 87.45, 100.73, 100.27, 105.00]

# Calculate error bar values for 5-bit
errors_low_5bit = [capacities_5bit[i] - ci_low_5bit[i] for i in range(len(capacities_5bit))]
errors_high_5bit = [ci_high_5bit[i] - capacities_5bit[i] for i in range(len(capacities_5bit))]
errors_5bit = [errors_low_5bit, errors_high_5bit]

# Create the plot with higher DPI for better quality
plt.figure(figsize=(12, 7), dpi=100)

# Plot 4-bit data with error bars
plt.errorbar(msg_lengths_4bit, capacities_4bit, 
             yerr=errors_4bit, 
             fmt='o-', 
             color='#0052cc',
             ecolor='#0052cc', 
             capsize=4, 
             linewidth=2, 
             label='4-bit Encoding')

# Plot 5-bit data with error bars
plt.errorbar(msg_lengths_5bit, capacities_5bit, 
             yerr=errors_5bit, 
             fmt='o-', 
             color='#00b050',
             ecolor='#00b050', 
             capsize=4, 
             linewidth=2, 
             label='5-bit Encoding')

# Configure plot styling
plt.grid(True, linestyle='--', alpha=0.7)
plt.title('Covert Channel Capacity vs Message Length', fontsize=16, fontweight='bold', pad=15)
plt.xlabel('Message Length (bytes)', fontsize=14, labelpad=10)
plt.ylabel('Capacity (bits/s)', fontsize=14, labelpad=10)

# Set x-axis to logarithmic scale for better visualization of wide range
plt.xscale('log')
plt.xlim(3, 140)  # Slightly adjusted to show all points clearly
plt.ylim(30, 110)

# Create custom x-ticks for better readability
x_ticks = [4, 8, 16, 32, 64, 128]
plt.xticks(x_ticks, [str(x) for x in x_ticks])

# Add subtle background shading for readability
plt.axhspan(30, 110, facecolor='#f8f9fa', alpha=0.5)

# Add legend with better positioning
plt.legend(loc='lower right', frameon=True, fontsize=12)

# Add explanatory subtitle as text
# plt.figtext(0.5, 0.92, 'Comparison of 4-bit and 5-bit encoding with 95% confidence intervals', 
#             ha='center', fontsize=12, color='#606060')

# Add annotations for key insights
# plt.annotate('Initial capacity growth', xy=(12, 55), xytext=(10, 45),
#              arrowprops=dict(facecolor='black', shrink=0.05, width=1.5, headwidth=7),
#              fontsize=10)

# plt.annotate('Performance plateau', xy=(96, 83), xytext=(70, 70),
#              arrowprops=dict(facecolor='black', shrink=0.05, width=1.5, headwidth=7),
#              fontsize=10)

# plt.annotate('5-bit advantage increases', xy=(64, 97), xytext=(40, 105),
#              arrowprops=dict(facecolor='black', shrink=0.05, width=1.5, headwidth=7),
#              fontsize=10)

# Make layout tight
plt.tight_layout()

# Save to file
plt.savefig('covert_channel_capacity.png', dpi=300, bbox_inches='tight')
