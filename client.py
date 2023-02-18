import socket

port = int(input('Enter port:\n'))
ip = input('Enter IP:\n')

def send_to_xclient(message, server_address, client_address = 1024):
    UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    UDPClientSocket.sendto(str.encode(str({'message': message, 'address': server_address})), Xclient_address)
    MessageFromServer = UDPClientSocket.recvfrom(client_address)
    message = "Message from Server {}".format(MessageFromServer[0])
    print(message)

Xclient_address = (ip, port)