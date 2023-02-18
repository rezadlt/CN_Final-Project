import multiprocessing as mp
import socket
import logging
import sys
import argparse
import json
import threading

servers = {}
lock = mp.Lock()
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-s', '--server', required=True,
                        help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")

    args = parser.parse_args()
    return args

def handle_tcp_conn_send(tcp_conn, udp_socket):
    print('hi')
    while True:
        msg, addr = udp_socket.recvfrom(1024)
        print(msg.decode())
        tcp_conn.send(msg)

if __name__ == "__main__":
    args = parse_input_argument()
    
    tcp_server_ip = args.server.split(':')[0]
    tcp_server_port = int(args.server.split(':')[1])
    tcp_server_addr = (tcp_server_ip, tcp_server_port)
    sock.bind(tcp_server_addr)
    sock.listen()
    conn, _ = sock.accept()
    try:
        while True:
            segment = conn.recv(1024)
            print(f'msg received: {segment}')
            segment = json.loads(segment.decode())
            rmt = segment['rmt']
            data = segment['data']
            if not rmt[1] in servers.keys():
                try:
                    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
                    mp.Process(target=handle_tcp_conn_send,
                                args=(conn, udp_socket)).start()
                except socket.error as e:
                    logging.error("(Error) Error openning the UDP socket: {}".format(e))
                    logging.error("(Error) Cannot open the UDP socket {}:{} or bind to it".format(rmt))
                    sys.exit(1)
                servers[rmt[1]] = udp_socket
            servers[rmt[1]].sendto(data.encode(), (rmt[0], rmt[1]))
    except KeyboardInterrupt:
        logging.info("Closing the TCP connection...")
