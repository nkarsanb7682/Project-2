"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Nathan Reed, Michelle Tran, Neel Karsanbhai



"""

import socket
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64decode,b64encode
host = "localhost"
port = 10001
pubKey = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9UWWRhq/n2B/29hVbNIuSvBEx
SndLNUW5WDyK7SIFEJPMdotPIZAWRdk0M8KRBcKrO3mlB/INGZYSsc+ibJ/KCsYh
Rg4i/EIzZ/nOAIWZefgXcAIiOViIAUc3//vaSgHbhpVHUmbw0cIGef5wOhuSO0Tx
ino8D2g2gl3j459lVQIDAQAB
-----END PUBLIC KEY-----
"""


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)


# TODO: Generate a cryptographically random AES key
def generate_key():
    # Return a string of size random bytes
    # AES encryption needs a 16 byte key
    return os.urandom(16);
    pass


# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function    
    key = RSA.importKey(pubKey)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(session_key)
    pass


# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # CBC: each block of plaintext is XOR w/previous ciphertext block before being encrypted
    # "new" creates new AES cipher
    enc = AES.new(session_key, AES.MODE_ECB)
    return enc.encrypt(message)
    pass

# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # CBC: each block of plaintext is XOR w/previous ciphertext block before being encrypted
    # "new" creates new AES cipher
    dec = AES.new(session_key, AES.MODE_ECB)
    return dec.decrypt(message)
    pass


# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = input("What's your username? ")
    password = input("What's your password? ")

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()
        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)

        # TODO: Encrypt message and send to server
        encryptMessage = encrypt_message(pad_message(message), key)
        send_message(sock, encryptMessage)

        # TODO: Receive and decrypt response from server
        receiveMessage = receive_message(sock)
        msg = decrypt_message(receiveMessage, key)
        if msg.decode().rstrip() != "authenticated":
            print("username or password incorrect")
        else:
            print("user successfully authenticated!")

    finally:
        print('closing socket')
        sock.close()


if __name__ in "__main__":
    main()
