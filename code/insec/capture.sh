#!/bin/bash
# capture.sh
#   launches receiver.py
#   captures raw SYN packets into a .pcap

IFACE="eth0"
OUTDIR="/code/insec/ml_dataset"
TIMESTAMP=$(date +%m-%d-%H%M)

PCAP_OUT="$OUTDIR/raw_pcaps/syn_capture_${TIMESTAMP}.pcap"
CSV_OUT="$OUTDIR/csv_capture_${TIMESTAMP}.csv"

RECV_SCRIPT="/code/insec/covert-receiver.py"
PYTHON_BIN="python3"

if [ ! -d "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
fi

echo "Starting receiver: $RECV_SCRIPT"

$PYTHON_BIN "$RECV_SCRIPT" --timeout 5 &
RECV_PID=$!

echo "Capturing raw SYN packets to PCAP → $PCAP_OUT"

tshark -i "$IFACE" -s0 -w "$PCAP_OUT" \
    "tcp[tcpflags] & tcp-syn != 0"  & PCAP_PID=$!

wait $RECV_PID

echo "receiver.py has exited (PID $RECV_PID). Stopping captures."
kill $PCAP_PID 2>/dev/null
wait $PCAP_PID 2>/dev/null

# tshark -r $PCAP_OUT -V > $OUTDIR/captured_${TIMESTAMP}.txt

tcpdump -nn -tttt -r  $PCAP_OUT \
    "tcp[tcpflags] & tcp-syn != 0" > $OUTDIR/captured_${TIMESTAMP}.txt

echo "all done"
