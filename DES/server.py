import os
import time
import socket
import string
from binascii import hexlify
from des import DES_Algorithm
from memory_profiler import profile
from diffie_hellman import getLargePrimeNumber, getPrimitiveRoot, keyGeneration, sharedKeyGeneration

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
def decryptAndReceive(message, DES_key, fileSize):
    # calculate time taken to decrypt
    start, cpu_start = time.time(), time.process_time()
    message = DES_Algorithm(text=message, key=DES_key, encrypt=False).DES()
    end, cpu_end = time.time(), time.process_time()
    # print("\nMessage Decrypted: ", message)

    time_taken = (end - start)
    cpu_time_taken = (cpu_end - cpu_start)
    throughput = fileSize * 0.001 / time_taken

    print(f"\nTime taken to decrypt: {time_taken * 1000:.2f} ms")
    print(f"CPU Time taken to decrypt: {cpu_time_taken * 1000:.2f} ms")
    print(f"Decryption Throughput: {throughput:.2f} kB/s\n")


def main():
    filename = input("Enter the file name: ")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((serverIP, serverPort))
    server.listen(1)  # max backlog of connections

    # Establishing the connection
    print("Establishing connection with Client...")
    client_sock, address = server.accept()
    print("Connection established with Client!\n")

    # Setting the Global Parameters
    p = getLargePrimeNumber(1000, 2000)
    q = getPrimitiveRoot(p, True)

    print("Forwarding Global Parameters to Client...\n")
    client_sock.send(str(p).encode())
    # Time lag needed else p & q concatenate for some reason
    time.sleep(2)
    client_sock.send(str(q).encode())

    # Generating the Public-Private Key Pair
    privateServer, publicServer = keyGeneration(p, q)
    # time.sleep(2)

    print("Server Public Key: ", publicServer)
    print("Server Private Key: ", privateServer)

    # Sending the Server Public Key
    client_sock.send(str(publicServer).encode())

    # Receiving the Public Key from Client
    publicClient = int(client_sock.recv(9000).decode())
    print("\nClient Public Key: ", publicClient)

    # time.sleep(2)

    key = int(str(sharedKeyGeneration(publicClient, privateServer, p)), 16)
    DES_key = keyGenerationForDES(p, q, key)

    print("\nShared Key: ", hex(key))
    print("DES Key: ", DES_key)

    filesize = os.path.getsize(f"../{filename}")
    print(f"File Size: {filesize * 0.001} kB\n")

    message = client_sock.recv(9999999).decode()
    # print("\nActual Message Received: ", hexlify(bytes(message, "utf-8")))


    decryptAndReceive(message, DES_key, filesize)
    


if __name__ == '__main__':
    main()