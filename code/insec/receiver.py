import socket, os
import sys
import string
import argparse
from itertools import permutations
from scapy.all import sniff, TCP


def build_permutations_map(base_options, bits):
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
    rev = {}
    for bits_val, opt_list in perm_map.items():
        rev[tuple(opt_list)] = bits_val
    return rev

def normalize_options(opt):
    """
    Normalize an option tuple. For 'SAckOK', convert b'' to ''
    """
    key, value = opt
    if key == 'SAckOK' and isinstance(value, bytes):
        return (key, value.decode('utf-8'))
    return opt

def adjust_options(options):
    """
    Remove any OS-added options such as 'EOL' and normalize opiton values. Returns cleaned list of options.
    """
    new_options = []
    for opt in options:
        if opt[0] == 'EOL':
            continue
        new_options.append(normalize_options(opt))
    return new_options


decoded_bits = []

def process_packet(pkt):
    if pkt.haslayer(TCP):
        # print(pkt[TCP])
        tcp_layer = pkt[TCP]
        # print(tcp_layer)
        if (tcp_layer.flags & 0x02) and tcp_layer.dport == 1234: # checks if the packet is SYN(0x02)
            # print("asdasd")
            options = adjust_options(tcp_layer.options)
            options_tuple = tuple(options)

            if options_tuple in reversed_mapping:
                chunk = reversed_mapping[options_tuple]
                # print(chunk)
                decoded_bits.append(chunk)

                # print(f"Received covert chunk: {chunk}")

def decode_message(bits_list):
    full_bit_string = "".join(bits_list)

    header_bits = full_bit_string[:16]
    msg_len = int(header_bits, 2)
    needed_bits = 8 * msg_len
    msg_bits = full_bit_string[16:16 + needed_bits]
    message = ""

    for i in range(0, len(msg_bits), 8):
        byte = msg_bits[i:i + 8]
        
        #padding if necessary
        if len(byte) < 8: 
            byte = byte.ljust(8, '0')

        #convert
        char_code = int(byte, 2)
        message += chr(char_code)
        # print("added char:", chr(char_code))
        
    # print("whole message", message)
    return message

def decrypt(message):
    key = "awUh7J9?lrt+35kIf09"
    decrypted = ""
    keylen = len(key)
    for i, ch in enumerate(message):
        decrypted += chr(ord(ch) ^ ord(key[i % keylen]))
    return decrypted

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Covert Receiver")

    parser.add_argument("--bits", type=int, default=4, choices=[4, 5],
                        help="Number of bits encoded per packet (4 or 5). Make sure covert sender and covert receiver has the same number of bits to encode and decode.")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Timeout in seconds for sniffing before decoding.")
    args = parser.parse_args()

    if args.bits == 4:
        base_options = [('MSS', 1460), ('WScale', 10), ('NOP', None), ('SAckOK', '')]
    else:
        base_options = [('MSS', 1460), ('WScale', 10), ('NOP', None), ('SAckOK', ''), ('Timestamp', (0,0))]

    perm_map = build_permutations_map(base_options, args.bits)
    reversed_mapping = build_reversed_mapping(perm_map)

    print(f"Initialization done. Using {args.bits}-bit chunks (capacity: {2**args.bits} values).")
    print("Listening on interface 'eth0' for 'tcp and port 1234' packets...")

    sniff(iface="eth0", filter="tcp and port 1234", prn=process_packet, timeout=args.timeout)


    decoded_msg = decode_message(decoded_bits)
    # print("decoded msg: ", decoded_msg)

    decrypted_msg = decrypt(decoded_msg)
    print("Decrypting complete")
    print("Decrypted message: ", decrypted_msg)
