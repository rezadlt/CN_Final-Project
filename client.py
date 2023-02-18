import socket

HOST_Xclient = "127.0.0.1"
PORT_Xclient = 8010

port = int(input('Enter port:\n'))
ip = input('Enter IP:\n')

def send_to_xclient(message, server_address, address = 1024):
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.sendto(str.encode(str({'message': message, 'address': server_address})), Xclient_address)
    MessageFromServer = UDPClientSocket.recvfrom(address)
    message = "Message from Server {}".format(MessageFromServer[0])
    print(message)

Xclient_address = (ip, port)