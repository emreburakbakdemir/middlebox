#!/bin/bash
# covert-capture.sh
# Generates continuous covert channel traffic for ML training data collection

IFACE="eth0"
OUTDIR="/code/insec/captured"
TIMESTAMP=$(date +%m-%d-%H%M)

PCAP_OUT="$OUTDIR/covert_capture_${TIMESTAMP}.pcap"
COVERT_SCRIPT="/code/sec/covert-sender.py"
PYTHON_BIN="python3"

if [ ! -d "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
fi

# Parse command line arguments
DURATION=180  # Default 3 minutes
BITS=4        # Default 4-bit encoding
DELAY=0.5     # Default delay between packets
INTENSITY="medium"  # low, medium, high

show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --duration SECONDS    Duration of capture (default: 180)"
    echo "  --bits 4|5           Encoding bits per packet (default: 4)"
    echo "  --delay SECONDS      Delay between packets (default: 0.5)"
    echo "  --intensity low|medium|high  Traffic intensity (default: medium)"
    echo "  --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --duration 300 --bits 5 --delay 0.1"
    echo "  $0 --intensity high --duration 600"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --bits)
            BITS="$2"
            if [[ "$BITS" != "4" && "$BITS" != "5" ]]; then
                echo "Error: bits must be 4 or 5"
                exit 1
            fi
            shift 2
            ;;
        --delay)
            DELAY="$2"
            shift 2
            ;;
        --intensity)
            INTENSITY="$2"
            if [[ "$INTENSITY" != "low" && "$INTENSITY" != "medium" && "$INTENSITY" != "high" ]]; then
                echo "Error: intensity must be low, medium, or high"
                exit 1
            fi
            shift 2
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Set intensity parameters
case $INTENSITY in
    "low")
        MESSAGE_INTERVAL=15     # Send message every 15 seconds
        BURST_SIZE=1           # 1 message per burst
        ;;
    "medium")
        MESSAGE_INTERVAL=8      # Send message every 8 seconds
        BURST_SIZE=2           # 2 messages per burst
        ;;
    "high")
        MESSAGE_INTERVAL=3      # Send message every 3 seconds
        BURST_SIZE=3           # 3 messages per burst
        ;;
esac

echo "🕵️ Starting covert channel traffic generation"
echo "Duration: ${DURATION}s"
echo "Encoding: ${BITS}-bit"
echo "Delay: ${DELAY}s"
echo "Intensity: $INTENSITY"
echo "Output: $PCAP_OUT"

# Predefined covert messages for variety
COVERT_MESSAGES=(
    "Secret message 1"
    "Covert channel test"
    "Hidden communication"
    "ML training data"
    "Phase 3 experiment"
    "Steganographic packet"
    "TCP options encoding"
    "Network security test"
    "Data exfiltration sim"
    "Encrypted payload"
    "Bypass detection"
    "Channel established"
    "Information transfer"
    "Subliminal message"
    "Protocol manipulation"
    "Option field abuse"
    "Timing pattern test"
    "Encoding verification"
    "Transmission complete"
    "Security assessment"
)

# Start packet capture
echo "📡 Starting packet capture..."
tshark -i "$IFACE" -w "$PCAP_OUT" "tcp[tcpflags] & tcp-syn != 0" &
CAPTURE_PID=$!

echo "Packet capture started (PID: $CAPTURE_PID)"
sleep 2  # Let capture initialize

echo "🚀 Starting covert traffic generation..."

# Function to send a covert message
send_covert_message() {
    local message="$1"
    local msg_bits="$2"
    local msg_delay="$3"
    
    echo "  📨 Sending: '$message' (${msg_bits}-bit, ${msg_delay}s delay)"
    
    "$PYTHON_BIN" "$COVERT_SCRIPT" \
        --msg "$message" \
        --bits "$msg_bits" \
        --delay "$msg_delay" &
    
    local sender_pid=$!
    
    # Don't wait for completion to allow overlapping
    return 0
}

# Function to generate varied parameters
get_varied_delay() {
    # Add ±20% random variation to base delay
    local base_delay="$1"
    local variation=$(echo "scale=3; $base_delay * 0.2" | bc -l)
    local random_factor=$(echo "scale=3; ($RANDOM % 200 - 100) / 100" | bc -l)
    local varied_delay=$(echo "scale=3; $base_delay + ($variation * $random_factor)" | bc -l)
    
    # Ensure minimum delay of 0.1s
    local min_delay=0.1
    if (( $(echo "$varied_delay < $min_delay" | bc -l) )); then
        varied_delay=$min_delay
    fi
    
    echo "$varied_delay"
}

# Main traffic generation loop
start_time=$(date +%s)
end_time=$((start_time + DURATION))
message_counter=0

while [ $(date +%s) -lt $end_time ]; do
    current_time=$(date +%s)
    remaining=$((end_time - current_time))
    
    if [ $remaining -le 0 ]; then
        break
    fi
    
    echo "⏱️  Time remaining: ${remaining}s"
    
    # Send burst of messages
    for ((i=1; i<=BURST_SIZE; i++)); do
        # Select random message
        msg_index=$((RANDOM % ${#COVERT_MESSAGES[@]}))
        message="${COVERT_MESSAGES[$msg_index]} #$message_counter"
        
        # Vary parameters occasionally
        current_bits=$BITS
        current_delay=$(get_varied_delay "$DELAY")
        
        # 20% chance to use different bit encoding
        if [ $((RANDOM % 5)) -eq 0 ]; then
            if [ "$BITS" = "4" ]; then
                current_bits=5
            else
                current_bits=4
            fi
        fi
        
        send_covert_message "$message" "$current_bits" "$current_delay"
        message_counter=$((message_counter + 1))
        
        # Small delay between burst messages
        if [ $i -lt $BURST_SIZE ]; then
            sleep 2
        fi
    done
    
    # Wait for next message interval
    echo "💤 Waiting ${MESSAGE_INTERVAL}s until next burst..."
    sleep "$MESSAGE_INTERVAL"
done

echo "⏹️  Stopping covert traffic generation..."

# Give last messages time to complete
sleep 5

# Stop packet capture
echo "📡 Stopping packet capture..."
kill $CAPTURE_PID 2>/dev/null
wait $CAPTURE_PID 2>/dev/null

# Generate summary
if [ -f "$PCAP_OUT" ]; then
    PACKET_COUNT=$(tshark -r "$PCAP_OUT" -T fields -e frame.number 2>/dev/null | wc -l)
    FILE_SIZE=$(du -h "$PCAP_OUT" | cut -f1)
    
    echo "✅ Covert traffic capture complete!"
    echo "📊 Summary:"
    echo "  Messages sent: $message_counter"
    echo "  Packets captured: $PACKET_COUNT"
    echo "  File size: $FILE_SIZE"
    echo "  Encoding used: ${BITS}-bit (with variations)"
    echo "  Base delay: ${DELAY}s (with variations)"
    echo "  Intensity: $INTENSITY"
    
    # Create detailed label file
    echo "pcap_file,label,message_count,packet_count,duration,bits,delay,intensity,timestamp" > "$OUTDIR/covert_labels_${TIMESTAMP}.csv"
    echo "$(basename "$PCAP_OUT"),covert,$message_counter,$PACKET_COUNT,$DURATION,$BITS,$DELAY,$INTENSITY,$TIMESTAMP" >> "$OUTDIR/covert_labels_${TIMESTAMP}.csv"
    
    # Generate readable packet summary
    echo "📝 Generating packet analysis..."
    tshark -r "$PCAP_OUT" -T fields \
        -e frame.time_relative \
        -e ip.src -e ip.dst \
        -e tcp.srcport -e tcp.dstport \
        -e tcp.flags.syn \
        -e tcp.options \
        "tcp.flags.syn==1" > "$OUTDIR/covert_analysis_${TIMESTAMP}.txt" 2>/dev/null
    
    echo "📋 Files created:"
    echo "  PCAP: $PCAP_OUT"
    echo "  Labels: $OUTDIR/covert_labels_${TIMESTAMP}.csv"
    echo "  Analysis: $OUTDIR/covert_analysis_${TIMESTAMP}.txt"
    
else
    echo "❌ Error: PCAP file not created"
    exit 1
fi

echo ""
echo "🎯 Ready for ML feature extraction!"
echo "Next steps:"
echo "  1. Run feature extraction on this PCAP"
echo "  2. Combine with benign traffic data"
echo "  3. Train ML models"