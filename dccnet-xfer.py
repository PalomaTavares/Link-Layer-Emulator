from dccnet import DCCNet
import sys
import socket

class Server(DCCNet):
    def __init__(self, host, port, input, output):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((host, port))
        sock.listen(1)

        while True:
            client_socket, client_address = sock.accept()
            print(f"Accepted connection from {client_address}")
            
            dccnet_instance = DCCNet(host=client_address[0], port=client_address[1], sock=client_socket, input=input, output=output)
            dccnet_instance.run()

class Client(DCCNet):
    def __init__(self, host, port, input, output):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")
        
        super().__init__(host, port, sock=sock, input=input, output=output)

        try:
            self.run()
        
        except Exception as e:
            print(f"Failed to connect: {e}")
        

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  To run as a server: python3 dccnet-xfer.py -s <PORT> <INPUT> <OUTPUT>")
        print("  To run as a client: python3 dccnet-xfer.py -c <IP>:<PORT> <INPUT> <OUTPUT>")
        sys.exit(1)

    mode = sys.argv[1]

    if len(sys.argv) != 5:
        print("Error: Missing port for server mode.")
        sys.exit(1)


    input = sys.argv[3]
    output = sys.argv[4]

    if mode == '-s':
        port = int(sys.argv[2])
        server = Server(host="127.0.0.1", port=port, input=input, output=output)

    elif mode == '-c':
        address = sys.argv[2]
        host, port = address.split(':')

        try:
            port = int(port)
        except ValueError:
            print("Error: Port must be an integer.")
            sys.exit(1)

        client = Client(host=host, port=port, input=input, output=output)

    else:
        print("Error: Invalid mode. Use '-s' for server or '-c' for client.")
        sys.exit(1)

if __name__ == "__main__":
    main()