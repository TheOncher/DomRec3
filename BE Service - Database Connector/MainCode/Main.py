import socket
import base64
import json


def start_server(port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', port))
    server_socket.listen(1)
    print(f"Server started! Listening on port {port}...")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Connection from {addr} has been established!")
        data = client_socket.recv(1024)
        decoded_data = base64.b64decode(data)
        decoded_data = decoded_data.decode()
        # json_decoded_data = json.loads(fr'"{decoded_data}"')
        print(decoded_data)
        #json_decoded_data = json.loads(decoded_data)
        # print(type(json_decoded_data))
        # print(json_decoded_data)
        client_socket.close()


with open("json.json", "r") as j:
    jj = (j.read()).replace(" ", "")
    print(jj)
    jj = json.loads(jj)

print(jj)

# start_server(5090)
