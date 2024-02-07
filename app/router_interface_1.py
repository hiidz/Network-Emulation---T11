import socket
import time
from config import *

def handle_connection(conn, address):
    print(f"Connection from {address} established.")

    while True:
        data = conn.recv(1024)
        if not data:
            print(f"Connection from {address} closed.")
            break
        print(f"Received data from {address}: {data.decode()}")

    print(f"Connection with {address} closed.")
    conn.close()

interface = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
interface.bind((HOST, R1_1_PORT))
interface.listen(5)

print(f"Interface on {HOST}:{R1_1_PORT} waiting for connections...")

while True:
    conn, address = interface.accept()
    handle_connection(conn, address)
