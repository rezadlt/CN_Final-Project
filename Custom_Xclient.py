import socket
import threading


HOST_Xclient = "127.0.0.1"
PORT_Xclient = 8010
Xclient_SERVER = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
Xclient_SERVER.bind((HOST_Xclient, PORT_Xclient))

threading.Thread(target=receive_from_xclient).start()
threading.Thread(target=receive_from_server).start()

CLIENTS = {}
udp_to_tcp_queue = []


def handle_tcp_conn_recv(stcp_socket, udp_socket, incom_udp_addr):
    """
    read from tcp socket for the UDP segment received through the tunnel,
    then forward received segment to incom_udp_addr
    """
    pass


def handle_tcp_conn_send(stcp_socket, rmt_udp_addr, udp_to_tcp_queue):
    """
    get remote UDP ip and port(rmt_udp_addr) and Concat them then sending it to the TCP socket
    after that read from udp_to_tcp_queue for sendeig a UDP segment and update queue,
    don't forgot to block the queue when you are reading from it.
    """
    pass


def handle_udp_conn_recv(request):
    client_ip, client_port, Xserver_ip, Xserver_port, url = request.split('::')
    clients[url] = (client_ip, int(client_port))
    udp_to_tcp_queue.append((Xserver_ip, Xserver_port, url))

    # this part is only for test, response will be sent to client by handle_tcp_connection_recv
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(1.0)
    addr = (client_ip, int(client_port))
    client_socket.sendto(request.encode('ascii'), addr)


while True:
    request, address = Xclient_SERVER.recvfrom(1024)
    request = request.decode('ascii')
    print(f'received UDP request from client {address}')
    print(f'request:\t{request}\n')

    threading.Thread(target=handle_udp_conn_recv, args=(request,)).start()
    