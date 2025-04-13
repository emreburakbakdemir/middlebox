#!/usr/bin/env python3
import os
import argparse
import time
from scapy.all import IP, TCP, send
from itertools import permutations

def make_perm_map(base_options, bits):
    """
    Creates a mapping from a bit-string of length 'bits' to a unique permutation
    of the base_options. It uses the first 2**bits permutations.
    """

    required = 2 ** bits
    perms = list(permutations(base_options))
    perm_map = {}
    for i in range(required):
        bitstr = format(i, f'0{bits}b')
        perm_map[bitstr] = list(perms[i])
    return perm_map

def message_to_bitstream(message):
    """
    Encodes the message by first creating a 16-bit header (in binary) representing
    the message length in bytes, then concatenates the 8-bit ASCII encoding of each character.
    """

    msg_length = len(message)
    header = format(msg_length, '016b')  # 16-bit header: supports messages up to 65535 bytes
    bitstream = ''.join(f'{ord(c):08b}' for c in message)
    return header + bitstream

def bitstream_to_chunks(bitstream, bits):
    """
    Splits the given bitstream into fixed-length chunks (of 'bits' bits),
    padding the final chunk with zeros if necessary.
    """
    
    chunks = [bitstream[i:i+bits].ljust(bits, '0') for i in range(0, len(bitstream), bits)]
    return chunks

def send_covert_syn_chunks(dst_ip, dst_port, message, base_options, bits, delay):
    """
    Sends the covert message over the network by:
      1. Constructing a bitstream (header + encrypted message),
      2. Splitting it into chunks of 'bits' length,
      3. Mapping each chunk to a permutation of TCP options,
      4. Sending a TCP SYN packet with those options and an inter-packet delay.
    """

    permutations_map = make_perm_map(base_options, bits)
    full_bitstream = message_to_bitstream(message)
    chunks = bitstream_to_chunks(full_bitstream, bits)
    for chunk in chunks:
        options = permutations_map.get(chunk)
        if not options:
            print(f"Cannot encode chunk: {chunk}")
            continue
        pkt = IP(dst=dst_ip)/TCP(dport=dst_port, flags='S', options=options)
        send(pkt, verbose=0)
        # Uncomment the following line to print each sent chunk:
        # print(f"Sent SYN packet for bits '{chunk}'")
        time.sleep(delay)

def encrypt(message):
    """
    Performs a basic XOR encryption on the message using a fixed key.
    The key is applied cyclically over the message.
    """
    
    key = "awUh7J9?lrt+35kIf09"
    encrypted = ""
    keylen = len(key)
    for i, ch in enumerate(message):
        encrypted += chr(ord(ch) ^ ord(key[i % keylen]))
    return encrypted


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Sender")
    
    parser.add_argument("--msg", type=str, default="Hello InsecureNet!",
                        help="Message to send.")
    parser.add_argument("--bits", type=int, default=4, choices=[4,5],
                        help="Number of bits to encode per TCP SYN packet (4 or 5). Make sure covert sender and covert receiver have the same number of bits to encode and decode.")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Inter-packet delay in seconds.")
    
    # parser.add_argument("--key", type=str, default=None,
    #                     help="Optional shared key for XOR encryption.")
    
    args = parser.parse_args()

    dst_ip = os.getenv("INSECURENET_HOST_IP")
    dst_port = 1234

    message = args.msg
    key = ""

    if args.bits == 4:
        base_options = [('MSS', 1460),('WScale', 10),('NOP', None),('SAckOK', '')]
    else: # bits == 5
        base_options = [('MSS', 1460),('WScale', 10),('NOP', None),('SAckOK', ''),('Timestamp', (0,0))]

    encrypted_msg = encrypt(message)
    send_covert_syn_chunks(dst_ip, dst_port, encrypted_msg, base_options, args.bits, args.delay)
