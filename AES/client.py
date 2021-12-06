import socket
import DiffieHellman
import nacl.secret
import nacl.utils
from binascii import hexlify
import time
from memory_profiler import profile

import AES

@profile
def encryptAndSend(message, sock, aes, filesize):
    # print('Actual message: "%s"\n' % message)
    
    start, cpu_start = time.time(), time.process_time()
    encrypted = aes.encrypt(message.encode())
    end, cpu_end = time.time(), time.process_time()

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = filesize * 0.001 / time_taken if time_taken != 0 else float('inf')

    print(f"Time taken to encrypt: {time_taken * 1000000:.2f} us")
    print(f"CPU Time taken to encrypt: {cpu_time_taken * 1000000:.2f} us")
    print(f"Encryption Throughput: {throughput:.2f} kB/s\n")

    # print("Encrypted message:", hexlify(encrypted), "\n")
    sock.send(encrypted)

def main():

    input_file = str(input("Enter the file name: "))

    # Initialize Diffie Hellman object so private and public keys are generated.
    client = DiffieHellman.D_H()

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    print('Connecting to Server...')
    server_address = ('localhost', 5555)
    sock.connect(server_address)
    print('Connection established with Server.\n')

    # send filename to server
    sock.sendall(input_file.encode())

    # Send Client's public key to the server so the Diffie hellman key exchange can happen.
    # And cast the key over to string so we can send it over the socket.
    sock.sendall(str(client.pubKey).encode())

    # Receive servers public key so we can generate the final (secret) key.
    data = sock.recv(9000)

    # Generate the secret key and cast the incoming key to int from str.
    client.genKey(int(data))
    print("Secret key:", hexlify(client.getKey()), "\n")

    # Initialize the SALT object and pass in the secret key.
    aes = nacl.secret.SecretBox(client.getKey())

    with open(f'../{input_file}', 'r') as f:
        message = f.read()
        filesize = len(message)

    print(f"File Size: {filesize * 0.001} kB\n")

    encryptAndSend(message, sock, aes, filesize)

if __name__ == '__main__':
    main()
