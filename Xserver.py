import multiprocessing as mp
import socket
import logging
import sys
import argparse
import json
import threading
import ssl
import asyncio

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
    print('salam')
    while True:
        message, address = udp_socket.recvfrom(1024)
        print(message.decode())
        tcp_conn.send(message)

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

def parse_input_argument():
    parser = argparse.ArgumentParser(description='This is a client program that create a tunnel\
                                                  to the server over various TCP connections.')

    parser.add_argument('-s', '--server', required=True,
                    help="The IP address and (TCP) port number of the tunnel server.\
                               The format is 'server ip:server port'.")
    args = parser.parse_args()
    return args

args = parse_input_argument()
    
tcp_server_ip = args.server.split(':')[0]
tcp_server_port = int(args.server.split(':')[1])

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
sock.bind((tcp_server_ip, tcp_server_port))

count = 0

while True:
    count += 1
    message, address = sock.recvfrom(1024)
    print(f"App server recieved from {address} message: {message}")
    sock.sendto(f"app server from port {tcp_server_port} sends {count}".encode(), address)

N_FORMAT = 'ascii'
async def handle_connection(reader, writer):
    address = writer.get_extra_info('peername')
    print('Connection established with {}'.format(address))
    destination_address = parse_address((await reader.readexactly(10)).decode(N_FORMAT))
    print('client connection is: {}'.format(address))
    sock = await asyncudp.create_socket(remote_addr = destination_address)
    writer.write(b'ack')
    await writer.drain()
    task1 = asyncio.create_task(reader, sock)
    task2 = asyncio.create_task(sock, writer)
    await task1
    await task2
    print('Done with {}'.format(address))


def setup_server():
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.options |= ssl.OP_NO_TLSv1
    ssl_ctx.options |= ssl.OP_NO_TLSv1_1
    ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
    ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ssl_ctx.load_cert_chain('server_cert.pem', keyfile='server_key.pem')
    ssl_ctx.load_verify_locations(cafile='server_ca.pem')
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    ssl_ctx.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
    loop = asyncio.get_event_loop()
    coroutine = asyncio.start_server(handle_connection,
                                     '127.0.0.1',
                                     8080,
                                     ssl=ssl_ctx,
                                     loop=loop)
    server = loop.run_until_complete(coroutine)
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    loop.run_forever()
    