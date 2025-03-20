import os
import socket
import time

def udp_sender():
    host = os.getenv('INSECURENET_HOST_IP')
    port = 8888
    message = "Hello, InSecureNet!"
    num_pkt = 0
    total_rtt = 0

    if not host:
        print("SECURENET_HOST_IP environment variable is not set.")
        return

    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
                    
        #start_time = time.time()

        while num_pkt < 100:
            # Send message to the server

            start_time = time.time()

            sock.sendto(message.encode(), (host, port))
            print(f"Message sent to {host}:{port}")


            # Receive response from the server
            response, server = sock.recvfrom(4096)
            print(f"Response from server: {response.decode()}")

            end_time = time.time()
            rtt = (end_time - start_time) * 1000
            total_rtt += rtt

            # Sleep for 1 second
            #time.sleep(1)
            num_pkt += 1

        #end_time = time.time()
        #rtt = (end_time - start_time) * 1000
        #print(f"RTT: {rtt:.3f} ms")

    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

    #avg_rtt = rtt / num_pkt
    avg_rtt = total_rtt / num_pkt
    print(f"Average RTT: {avg_rtt:.3f} ms")

if __name__ == "__main__":
    udp_sender()