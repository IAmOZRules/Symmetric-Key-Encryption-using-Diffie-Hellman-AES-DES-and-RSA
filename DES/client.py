import os
import time 
import socket
import string
from binascii import hexlify
from des import DES_Algorithm
from memory_profiler import profile
from diffie_hellman import keyGeneration, sharedKeyGeneration

serverPort = 8001
serverIP = "127.0.0.1"


def keyGenerationForDES(p, q, sharedKey):
    '''
    This is just a function to generate a key of sufficient length
    for the DES Algorithm to work using the shared key formed and the
    global parameters
    '''
    mapping = {}
    for index, letter in enumerate(string.ascii_letters):
        mapping[index] = letter

    val = str(sharedKey * p * q)

    finalKey = []
    for index in range(0, len(val), 2):
        finalKey.append(mapping[int(val[index:index + 1]) % len(mapping)])

    while len(finalKey) < 8:
        finalKey += finalKey

    return "".join(finalKey[:8])


@profile
def encryptAndSend(message, DES_key, client, fileSize):
    # message = input("\nEnter the message to be sent to the server: ")
    start, cpu_start = time.time(), time.process_time()
    encryptedMessage = DES_Algorithm(text=message, key=DES_key, encrypt=True).DES()
    end, cpu_end = time.time(), time.process_time()
    client.send(encryptedMessage.encode())
    # print("\nEncrypted Message: ", hexlify(bytes(encryptedMessage, "utf-8")))

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = fileSize * 0.001 / time_taken
    
    print(f"\nTime taken to encrypt: {time_taken * 1000:.2f} ms")
    print(f"CPU Time taken to encrypt: {cpu_time_taken * 1000:.2f} ms")
    print(f"Encryption Throughput: {throughput:.2f} kB/s\n")

def main():

    filename = input("Enter the file name: ")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Establishing the connection
    print("Establishing connection with Server...")
    client.connect((serverIP, serverPort))
    print("Connection established with Server!\n")

    # Sending the file name to the server
    # client.send(filename.encode())

    print("Forwarding Global Parameters to Server...\n")
    # Getting the global parameters
    p = int(client.recv(9000).decode())
    q = int(client.recv(9000).decode())

    print(f"Large Prime number set to: {p}")
    print(f"Primitive Root is set to: {q}\n")

    # Generating the Public-Private Key Pair
    privateClient, publicClient = keyGeneration(p, q)
    # time.sleep(2)

    print(f"Client Private Key: {privateClient}")
    print(f"Client Public Key: {publicClient}\n")

    # Recieving the Public Key of Server
    publicServer = int(client.recv(50000).decode())
    print(f"Server Public Key: {publicServer}\n")

    # Sending the Public Key
    client.send(str(publicClient).encode())

    # time.sleep(2)


    # Getting the key to be used for DES
    key = int(str(sharedKeyGeneration(publicServer, privateClient, p)), 16)
    DES_key = keyGenerationForDES(p, q, key)

    print("Shared Key: ", hex(key))
    print("DES Key: ", DES_key)

    # read from lorem.txt
    with open(f"../{filename}", "r") as f:
        message = f.read()
        filesize = len(message)

    # filesize = os.path.getsize("lorem.txt")
    print(f"File Size: {filesize * 0.001} kB\n")

    encryptAndSend(message, DES_key, client, filesize)
    


if __name__ == '__main__':
    main()