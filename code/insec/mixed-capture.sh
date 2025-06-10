#!/bin/bash
# unified-capture.sh
# Single packet capture that handles both benign and covert traffic for ML training

OUTDIR="/code/insec/captured"
TIMESTAMP=$(date +%m-%d-%H%M)
DURATION="${1:-420}"  # Default 7 minutes
SESSION_TYPE="${2:-mixed}"

PCAP_OUT="$OUTDIR/${SESSION_TYPE}_capture_${TIMESTAMP}.pcap"

mkdir -p "$OUTDIR"

echo "📡 Unified Traffic Capture for ML Training"
echo "=========================================="
echo "Session Type: $SESSION_TYPE"
echo "Duration: ${DURATION}s ($(($DURATION/60))min)"
echo "Output: $PCAP_OUT"
echo ""

echo "🎯 Key Insight: For ML training, we don't need to DECODE covert messages"
echo "   We just need to CAPTURE and LABEL the traffic patterns!"
echo ""

# Instructions for mixed traffic
if [ "$SESSION_TYPE" = "mixed" ]; then
    echo "🌐 Mixed Traffic Collection Instructions:"
    echo "   This capture will record ALL SYN packets (benign + covert)"
    echo "   The ML model will learn to distinguish them by their features"
    echo ""
    echo "🚨 SEC Container Commands:"
    echo "   1. Start benign traffic:"
    echo "      python3 /code/sec/benign-sender.py --duration $(($DURATION/60)) --target 10.0.0.21 &"
    echo ""
    echo "   2. Periodically inject covert traffic (every 45-60 seconds):"
    echo "      python3 /code/sec/covert-sender.py --msg 'Mixed traffic 1' --bits 4 --delay 0.5"
    echo "      (wait 60s)"
    echo "      python3 /code/sec/covert-sender.py --msg 'Mixed traffic 2' --bits 5 --delay 0.3"
    echo "      (wait 60s)"
    echo "      python3 /code/sec/covert-sender.py --msg 'Mixed traffic 3' --bits 4 --delay 0.7"
    echo "      ..."
    echo ""
elif [ "$SESSION_TYPE" = "covert" ]; then
    echo "🕵️ Covert Traffic Collection Instructions:"
    echo "   This capture will record covert SYN packets to port 1234"
    echo ""
    echo "🚨 SEC Container Commands:"
    echo "   bash /code/sec/continuous-covert.sh $DURATION"
    echo "   OR:"
    echo "   for i in {1..$(($DURATION/60))}; do bash /code/sec/send.sh; sleep 45; done"
    echo ""
elif [ "$SESSION_TYPE" = "benign" ]; then
    echo "📡 Benign Traffic Collection Instructions:"
    echo "   This capture will record normal SYN packets to various ports"
    echo ""
    echo "🚨 SEC Container Commands:"
    echo "   python3 /code/sec/benign-sender.py --duration $(($DURATION/60)) --target 10.0.0.21"
    echo ""
fi

echo "⏰ Starting capture in 10 seconds..."
echo "👆 Start SEC commands NOW!"

# Countdown
for i in {10..1}; do
    echo -ne "   ${i}...\r"
    sleep 1
done
echo ""

# Start unified packet capture
echo "📡 Starting unified packet capture..."
echo "   Capturing ALL SYN packets (benign and covert together)"

tshark -i eth0 -w "$PCAP_OUT" "tcp[tcpflags] & tcp-syn != 0" &
CAPTURE_PID=$!

echo "   📊 Capture PID: $CAPTURE_PID"
echo "   ⏰ Collecting for ${DURATION}s..."

# Progress monitoring with packet count updates
elapsed=0
while [ $elapsed -lt $DURATION ]; do
    sleep 30
    elapsed=$((elapsed + 30))
    remaining=$((DURATION - elapsed))
    
    # Count packets captured so far
    if [ -f "$PCAP_OUT" ]; then
        current_count=$(tshark -r "$PCAP_OUT" -T fields -e frame.number 2>/dev/null | wc -l)
        echo "   ⏱️  Progress: ${elapsed}/${DURATION}s | Packets: $current_count | Remaining: ${remaining}s"
    else
        echo "   ⏱️  Progress: ${elapsed}/${DURATION}s | Remaining: ${remaining}s"
    fi
done

# Stop capture
echo "   ⏹️  Stopping capture..."
sleep 5
kill $CAPTURE_PID 2>/dev/null
wait $CAPTURE_PID 2>/dev/null

# Analyze results
if [ -f "$PCAP_OUT" ]; then
    echo ""
    echo "📊 Capture Analysis:"
    
    total_packets=$(tshark -r "$PCAP_OUT" -T fields -e frame.number 2>/dev/null | wc -l)
    port_1234_packets=$(tshark -r "$PCAP_OUT" "tcp.dstport==1234" -T fields -e frame.number 2>/dev/null | wc -l)
    other_packets=$((total_packets - port_1234_packets))
    file_size=$(du -h "$PCAP_OUT" | cut -f1)
    
    echo "   📁 File: $PCAP_OUT"
    echo "   📦 Size: $file_size"
    echo "   📊 Total SYN packets: $total_packets"
    echo "   🕵️  Port 1234 (covert): $port_1234_packets"
    echo "   📡 Other ports (benign): $other_packets"
    
    if [ "$SESSION_TYPE" = "mixed" ]; then
        if [ $port_1234_packets -gt 0 ] && [ $other_packets -gt 0 ]; then
            covert_ratio=$(echo "scale=1; $port_1234_packets * 100 / $total_packets" | bc -l)
            echo "   🎯 Covert ratio: ${covert_ratio}%"
            echo "   ✅ Mixed traffic captured successfully!"
        else
            echo "   ⚠️  Warning: Missing benign or covert traffic"
        fi
    elif [ "$SESSION_TYPE" = "covert" ]; then
        if [ $port_1234_packets -gt 0 ]; then
            echo "   ✅ Covert traffic captured successfully!"
        else
            echo "   ⚠️  Warning: No covert traffic detected"
        fi
    elif [ "$SESSION_TYPE" = "benign" ]; then
        if [ $other_packets -gt 0 ]; then
            echo "   ✅ Benign traffic captured successfully!"
        else
            echo "   ⚠️  Warning: No benign traffic detected"
        fi
    fi
    
    # Quick TCP options analysis for covert packets
    if [ $port_1234_packets -gt 0 ]; then
        echo ""
        echo "🔍 Quick Covert Analysis (first 3 packets to port 1234):"
        tshark -r "$PCAP_OUT" "tcp.dstport==1234" -c 3 -T fields \
            -e frame.time_relative \
            -e tcp.options.mss.val \
            -e tcp.options.wscale.shift \
            -e tcp.options.sack_perm 2>/dev/null | \
        while read time mss wscale sack; do
            echo "   Time: ${time}s | MSS: $mss | WScale: $wscale | SACK: $sack"
        done
    fi
    
    # Create label entry
    echo "$(basename "$PCAP_OUT"),$SESSION_TYPE,$total_packets,$port_1234_packets,$other_packets" >> "$OUTDIR/labels_${TIMESTAMP}.csv"
    
    echo ""
    echo "✅ Unified capture complete!"
    echo "🎯 This PCAP contains both traffic types for ML training"
    
else
    echo "❌ Error: PCAP file not created"
    exit 1
fi

echo ""
echo "💡 ML Training Insight:"
echo "   The ML model will learn to distinguish covert vs benign packets by:"
echo "   - Port patterns (1234 vs others)"
echo "   - TCP option combinations and ordering"
echo "   - Option values (MSS, WScale, etc.)"
echo "   - Timing patterns"
echo ""
echo "🎯 No message decoding needed - pattern recognition is sufficient!"