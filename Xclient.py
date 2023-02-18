import multiprocessing as mp
import socket
import logging
from queue import Queue
import time
import sys
import argparse
import time
import json
import threading

lock = mp.Lock()
client = {}
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
address = {}

def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-ut', '--udp-tunnel', action='append', required=True,
                        help="Make a tunnel from the client to the server. The format is\
                              'listening ip:listening port:remote ip:remote port'.")
    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    parser.add_argument('-v', '--verbosity', choices=['error', 'info', 'debug'], default='info',
                        help="Determine the verbosity of the messages. The default value is 'info'.")

    args = parser.parse_args()
    return args

def read_n_byte_from_tcp_sock(sock, n):
    '''Just for read n byte  from tcp socket'''
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = sock.recv_into(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff

def handle_tcp_conn_recv(stcp_socket, udp_socket, incom_udp_addr):
    while True:
        try:
            segment = stcp_socket.recv(1024)
        except EOFError:
            logging.info("TCP connection closed")
            break
        udp_socket.sendto(segment, address[incom_udp_addr])

def handle_tcp_conn_send(stcp_socket, rmt_udp_addr, udp_to_tcp_queue):
    while True:
        lock.acquire()
        if udp_to_tcp_queue.qsize() > 0:
            segment = udp_to_tcp_queue.get()
            segment_json = {
                "data": segment.decode(),
                "rmt": rmt_udp_addr
            }
            segment = json.dumps(segment_json)
            print(segment_json)
            stcp_socket.sendall(segment.encode())
        time.sleep(5)
        lock.release()
            
def handle_udp_conn_recv(udp_socket, rmt_udp_addr, incom_udp_addr):
    if not udp_socket.getsockname()[1] in client.keys():
        q = Queue()
        mp.Process(target=handle_tcp_conn_send,
                    args=(sock, rmt_udp_addr, q)).start()

        mp.Process(target=handle_tcp_conn_recv,
                    args=(sock, udp_socket, incom_udp_addr)).start()

        client[udp_socket.getsockname()[1]] = q
        
    q = client[udp_socket.getsockname()[1]]
    while True:
        segment, addr = udp_socket.recvfrom(1024)
        address[incom_udp_addr] = addr
        print(f'udp msg received: {segment} from {addr}')
        q.put(segment)


if __name__ == "__main__":
    args = parse_input_argument()
    
    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    tcp_server_addr = (tcp_server_ip, tcp_server_port)
    sock.connect(tcp_server_addr)

    for tun_addr in args.udp_tunnel:
        tun_addr_split = tun_addr.split(':')
        udp_listening_ip = tun_addr_split[0]
        udp_listening_port = int(tun_addr_split[1])
        rmt_udp_ip = tun_addr_split[2]
        rmt_udp_port = int(tun_addr_split[3])
        rmt_udp_addr = (rmt_udp_ip, rmt_udp_port)
        try:
            udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
            udp_socket.bind((udp_listening_ip, udp_listening_port))
        except socket.error as e:
            logging.error("(Error) Error openning the UDP socket: {}".format(e))
            logging.error("(Error) Cannot open the UDP socket {}:{} or bind to it".format(udp_listening_ip, udp_listening_port))
            sys.exit(1)
        else:
            logging.info("Bind to the UDP socket {}:{}".format(udp_listening_ip, udp_listening_port))
    
        mp.Process(target=handle_udp_conn_recv,
                   args=(udp_socket, rmt_udp_addr, (udp_listening_ip, udp_listening_port))).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Closing the TCP connection...")

def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-s', '--server', required=True,
                    help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    args = parser.parse_args()
    return args

args = parse_input_argument()
    
udpserver_ip = args.server.split(':')[0]
udpserver_port = int(args.server.split(':')[1])

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

count = 0
while True:
    count += 1
    sock.sendto(f"sending app client port {udpserver_port} {count}".encode(), (udpserver_ip, udpserver_port))
    print(f"sending test port {udpserver_port} {count}".encode())
    message, addr = sock.recvfrom(1024)
    print(f"recieving app client from {addr} message: {messsage.decode()}")