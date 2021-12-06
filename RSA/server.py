import socket
import RSA_hybrid
import hashlib
import nacl.utils
import time
import os
from memory_profiler import profile

@profile
def decryptAndReceive(msg, Key1, filesize):
    start, cpu_start = time.time(), time.process_time()
    msg = RSA_hybrid.xor(msg, Key1)
    end, cpu_end = time.time(), time.process_time()

    # print ('\nReceived \"{}\"'.format(msg))

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = filesize * 0.001 / time_taken if time_taken != 0 else float('inf')
    
    print(f"\nTime taken to decrypt: {time_taken * 1000:.2f} ms")
    print(f"CPU Time taken to decrypt: {cpu_time_taken * 1000:.2f} ms")
    print(f"Decryption Throughput: {throughput:.2f} kB/s\n")

def main():
    # Create a TCP/IP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a port
    server_address = ('localhost',5555)
    sock.bind(server_address)

    # Listen for incoming connections.
    sock.listen(1)

    # Accepting the incoming traffic on server socket.
    print('Connecting to Client...')
    connection, client_address = sock.accept()
    print('Connection established with the Client.\n')

    # receive filename from client
    filename = connection.recv(11).decode()

    # Receive clients public key so we can generate the final (secret) key.
    client_Pubkey = connection.recv(9000).decode()
    print("Public Key:",client_Pubkey)
    
    shared_prime = connection.recv(9000).decode()
    print("Shared prime:",shared_prime)
    
    shared_base = connection.recv(9000).decode()
    print("Shared Base:",shared_base)
    
    X = (int(shared_base) ** int(client_Pubkey)) % int(shared_prime)
    print("\nX=",X)

    # Send our (server) public key.
    connection.sendall(str(X).encode())
    
    Y = connection.recv(9000)
    print("Y=",Y)
    
    K1 = pow(int(Y), int(client_Pubkey), int(shared_prime))
    Key1 = hashlib.sha256(str(K1).encode('utf-8')).hexdigest()

    # Generate the secret key and cast the incoming key to int from str.
    print("\nSecret key:", Key1)

    filesize = os.path.getsize(f"../{filename}");
    print(f"\nFile Size: {filesize * 0.001: .4f} kB\n")

    msg = connection.recv(9999999).decode()
    
    decryptAndReceive(msg, Key1, filesize)

if __name__ == '__main__':
    main()