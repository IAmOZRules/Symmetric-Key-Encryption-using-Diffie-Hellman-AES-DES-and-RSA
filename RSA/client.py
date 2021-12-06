import socket
import RSA_hybrid
import hashlib
import nacl.utils
import time
from memory_profiler import profile

@profile
def encryptAndSend(message, Key2, sock, filesize):
    start, cpu_start = time.time(), time.process_time()
    ciphertext = RSA_hybrid.xor(message, Key2)
    end, cpu_end = time.time(), time.process_time()

    sock.send(str(ciphertext).encode())

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = filesize * 0.001 / time_taken if time_taken != 0 else float('inf')
    
    print(f"\nTime taken to encrypt: {time_taken * 1000:.2f} ms")
    print(f"CPU Time taken to encrypt: {cpu_time_taken * 1000:.2f} ms")
    print(f"Encryption Throughput: {throughput:.2f} kB/s\n")


def main():
    filename = str(input("Enter the file name: "))

    # Initialize Diffie Hellman object so private and public keys are generated.
    client = RSA_hybrid.RSA()

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    print('Connecting to Server...')
    server_address = ('localhost', 5555)
    sock.connect(server_address)
    print('Connection established with the Server.\n')

    #send filname to server
    sock.send(filename.encode())

    # Send Client's public key to the server so the Diffie hellman key exchange can happen.
    # And cast the key over to string so we can send it over the socket.
    print("Public key:",client.public)
    sock.sendall(str(client.public).encode())

    print("Shared prime:",client.r) 
    sock.sendall(str(client.r).encode())

    print("Shared base:",client.q)
    sock.send(str(client.q).encode())

    # Receive servers public key so we can generate the final (secret) key.
    X = sock.recv(9000).decode()
    Y = (client.q ** client.private) % client.r
    sock.sendall(str(Y).encode())

    K2 = pow(int(X), client.private, client.r)
    Key2 = hashlib.sha256(str(K2).encode('utf-8')).hexdigest()

    # Generate the secret key and cast the incoming key to int from str.
    print("\nSecret key:", Key2 )

    with open(f"../{filename}", "r") as f:
        message = f.read()
        filesize = len(message)

    print(f"\nFile Size: {filesize * 0.001: .4f} kB\n")

    encryptAndSend(message, Key2, sock, filesize)

if __name__ == "__main__":
    main()