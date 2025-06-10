#!/bin/bash
# data-capture.sh
# Pure packet capture for ML training data (no covert receiver)

IFACE="eth0"
OUTDIR="/code/insec/ml_dataset"
TIMESTAMP=$(date +%m-%d-%H%M)

PCAP_OUT="$OUTDIR/raw_pcaps/syn_capture_${TIMESTAMP}.pcap"
CSV_OUT="$OUTDIR/csv_capture_${TIMESTAMP}.csv"


if [ ! -d "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
fi

# Parse command line arguments
DURATION=60
TRAFFIC_TYPE="benign"
LABEL=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --duration)
            DURATION="$2"
            shift 2
            ;;
        --type)
            TRAFFIC_TYPE="$2"
            shift 2
            ;;
        --label)
            LABEL="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--duration SECONDS] [--type benign|covert|mixed] [--label CUSTOM_LABEL]"
            exit 1
            ;;
    esac
done

# Set default label based on traffic type
if [ -z "$LABEL" ]; then
    LABEL="$TRAFFIC_TYPE"
fi

echo "📡 Starting packet capture for ML dataset"
echo "Duration: ${DURATION}s"
echo "Traffic type: $TRAFFIC_TYPE"
echo "Label: $LABEL"
echo "Output: $PCAP_OUT"

# Start packet capture
echo "Capturing raw SYN packets to PCAP → $PCAP_OUT"

tshark -i "$IFACE" -s0 -w "$PCAP_OUT" \
    "tcp[tcpflags] & tcp-syn != 0" &
PCAP_PID=$!

echo "Packet capture started (PID: $PCAP_PID)"
echo "Capturing for ${DURATION} seconds..."

# Wait for specified duration
sleep "$DURATION"

echo "Stopping packet capture..."
kill $PCAP_PID 2>/dev/null
wait $PCAP_PID 2>/dev/null

# Generate summary
PACKET_COUNT=$(tshark -r "$PCAP_OUT" -T fields -e frame.number | wc -l)

echo "✅ Capture complete!"
echo "Packets captured: $PACKET_COUNT"
echo "File size: $(du -h "$PCAP_OUT" | cut -f1)"

# Create label file
echo "pcap_file,label,packet_count,duration,timestamp" > "$OUTDIR/labels/labels_${TIMESTAMP}.csv"
echo "$(basename "$PCAP_OUT"),$LABEL,$PACKET_COUNT,$DURATION,$TIMESTAMP" >> "$OUTDIR/labels/labels_${TIMESTAMP}.csv"

# Generate text summary
tcpdump -nn -tttt -r "$PCAP_OUT" \
    "tcp[tcpflags] & tcp-syn != 0" > "$OUTDIR/captured/captured_${TIMESTAMP}.txt"

echo "📊 Summary saved to: $OUTDIR/labels_${TIMESTAMP}.csv"
echo "📝 Text dump saved to: $OUTDIR/captured_${TIMESTAMP}.txt"

echo "🎯 Ready for feature extraction!"