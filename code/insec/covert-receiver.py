#!/usr/bin/env python3
import argparse
from itertools import permutations
from scapy.all import sniff, TCP
import time
import os

decoded_bits = []
messages_received = 0


def build_permutations_map(base_options, bits):
    """
    Constructs a mapping from bit strings of length 'bits' to a unique permutation
    of the base_options.
    """

    required = 2 ** bits
    perms = list(permutations(base_options))
    if len(perms) < required:
        raise ValueError(f"Not enough permutations available with the given base_options for {bits} bits.")
    perm_map = {}
    for i in range(required):
        bitstr = format(i, f'0{bits}b')
        perm_map[bitstr] = list(perms[i])
    return perm_map

def build_reversed_mapping(perm_map):
    """
    Builds a reversed mapping that maps a tuple of options to the corresponding bit string.
    """

    rev = {}
    for bits_val, opt_list in perm_map.items():
        rev[tuple(opt_list)] = bits_val
    return rev

def normalize_options(opt):
    """
    Normalizes an option tuple.
    For 'SAckOK', converts b'' to an empty string ''.
    """

    key, value = opt
    if key == 'SAckOK' and isinstance(value, bytes):
        return (key, value.decode('utf-8'))
    return opt

def adjust_options(options):
    """
    Removes any OS-added options (such as 'EOL') and normalizes each option.
    Returns a cleaned list of options.
    """

    new_options = []
    for opt in options:
        if opt[0] == 'EOL':
            continue
        new_options.append(normalize_options(opt))
    return new_options



def process_packet(pkt):
    """
    Callback function for each sniffed packet:
      - It checks for TCP SYN packets on destination port 1234.
      - It adjusts and normalizes the TCP options.
      - If the options match one in the reversed mapping, it extracts the corresponding bit chunk.
      - It raises a KeyboardInterrupt for early exit when the full covert message is received.
    """

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        if (tcp_layer.flags & 0x02) and tcp_layer.dport == 1234:  # Check if SYN and destined for port 1234.
            options = adjust_options(tcp_layer.options)
            options_tuple = tuple(options)
            if options_tuple in reversed_mapping:
                chunk = reversed_mapping[options_tuple]
                decoded_bits.append(chunk)
                full_bits = "".join(decoded_bits)
                if len(full_bits) >= 16:
                    header = full_bits[:16]
                    msg_length = int(header, 2)
                    total_req = 16 + msg_length * 8
                    if len(full_bits) >= total_req:
                        raise KeyboardInterrupt  # Early exit when full message received.
            else:
                print("Unrecognized options:", options)

def decode_message(bits_list):
    """
    Decodes the accumulated bit chunks into a complete message.
    Uses the first 16 bits as a header indicating the message length (in bytes),
    and then extracts the corresponding number of message bits.
    """

    full_bit_string = "".join(bits_list)
    header_bits = full_bit_string[:16]
    msg_len = int(header_bits, 2)
    needed_bits = 8 * msg_len
    msg_bits = full_bit_string[16:16 + needed_bits]
    message = ""
    for i in range(0, len(msg_bits), 8):
        byte = msg_bits[i:i+8]
        if len(byte) < 8:
            byte = byte.ljust(8, '0')
        char_code = int(byte, 2)
        message += chr(char_code)
    return message

def decrypt(message):
    """
    Decrypts the XOR-encrypted message using a fixed shared key.
    """
    
    key  = "awUh7J9?lrt+35kIf09"
    decrypted = ""
    keylen = len(key)
    for i, ch in enumerate(message):
        decrypted += chr(ord(ch) ^ ord(key[i % keylen]))
    return decrypted



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Covert Receiver")
    parser.add_argument("--bits", type=int, default=4, choices=[4, 5],
                        help="Number of bits encoded per packet (4 or 5). Make sure covert sender and covert receiver have the same number of bits to encode and decode.")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Timeout in seconds for sniffing before decoding.")
    args = parser.parse_args()

    if args.bits == 4:
        base_options = [('MSS', 1460), ('WScale', 10), ('NOP', None), ('SAckOK', '')]
    else:
        base_options = [('MSS', 1460), ('WScale', 10), ('NOP', None), ('SAckOK', ''), ('Timestamp', (0,0))]

    perm_map = build_permutations_map(base_options, args.bits)
    reversed_mapping = build_reversed_mapping(perm_map)

    print(f"--Initialization done. Using {args.bits}-bit chunks (capacity: {2**args.bits} values).")
    print(f"--Listening on interface 'eth0' for 'tcp and port 1234' will exit after {args.timeout}")

    tout = args.timeout
    last_seen = time.time()
    while True:
        packets = sniff(
            iface="eth0",
            filter="tcp and port 1234",
            prn=process_packet,
            timeout=args.timeout,
            count=1
        )
        if packets:
            last_seen = time.time()
            continue
        else:
            silence = time.time() - last_seen
            if silence >= args.timeout:
                break


    # try:how 
    #     sniff(iface="eth0", filter="tcp and port 1234", prn=process_packet, timeout=args.timeout)
    # except KeyboardInterrupt:
    #     print("--Early Termination: complete message received.")


    decoded_msg = decode_message(decoded_bits)
    print(decoded_msg)
    decrypted_msg = decrypt(decoded_msg)
    print("--Decrypting complete")
    print("--Decrypted message: ", decrypted_msg)
