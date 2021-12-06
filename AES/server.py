import socket
from binascii import hexlify
import DiffieHellman
import nacl.secret
import nacl.utils
import os
from memory_profiler import profile
import time
import AES

@profile
def decryptAndReceive(connection, aes, filesize):
    msg = connection.recv(999999)
    # print("Received:", hexlify(msg), "\n")

    start, cpu_start = time.time(), time.process_time()
    decrypted = aes.decrypt(msg)
    end, cpu_end = time.time(), time.process_time()

    # print("Decrypted:", decrypted, "\n")

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = filesize * 0.001 / time_taken if time_taken != 0 else float('inf')

    print(f"Time taken to decrypt: {time_taken * 1000000:.2f} us")
    print(f"CPU Time taken to decrypt: {cpu_time_taken * 1000000:.2f} us")
    print(f"Decryption Throughput: {throughput:.2f} kB/s\n")

def main():
    # Initialize Diffie Hellman object so private and public keys are generated.
    server = DiffieHellman.D_H()

    # Create a TCP/IP socket.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to a port
    print('Connecting to client...')
    server_address = ('localhost',5555)
    sock.bind(server_address)

    # Listen for incoming connections.
    sock.listen(1)

    # Accepting the incoming traffic on server socket.
    connection, client_address = sock.accept()
    print("Connection established with Client.\n")

    # receive filename from client
    filename = connection.recv(11)

    # Receive clients public key so we can generate the final (secret) key.
    client_Pubkey = connection.recv(9000)

    # Send our (server) public key.
    connection.sendall(str(server.pubKey).encode())

    # Generate the secret key and cast the incoming key to int from str.
    server.genKey(int(client_Pubkey))
    print("Secret key:", hexlify(server.getKey()), "\n")

    # Initialize the SALT object and pass in the secret key.
    aes = nacl.secret.SecretBox(server.getKey())

    filesize = os.path.getsize(f"../{filename.decode()}")
    print(f"File Size: {filesize * 0.001} kB\n")

    decryptAndReceive(connection, aes, filesize)


if __name__ == '__main__':
    main()