"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Nathan Reed, Michelle Tran, Neel Karsanbhai



"""

import socket
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
host = "localhost"
port = 10001
privKey = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC9UWWRhq/n2B/29hVbNIuSvBExSndLNUW5WDyK7SIFEJPMdotP
IZAWRdk0M8KRBcKrO3mlB/INGZYSsc+ibJ/KCsYhRg4i/EIzZ/nOAIWZefgXcAIi
OViIAUc3//vaSgHbhpVHUmbw0cIGef5wOhuSO0Txino8D2g2gl3j459lVQIDAQAB
AoGAb6ed+6IwBNDWqVSha9UlrDj2+tcsXFLi+Fkt+9G3ir0oLiKMLvNgg4JWhA8y
5U08brj5GXgCLe+1LvlnuCfQZNfi3vm5BeSfEzLtu3fgxnTEs2wi/ZKaDyPue/Y+
/Secclem+hWvNcL6lk8wap3kwKqwoMjFsCA1/6VXfh834gECQQDHrH/daHLdofls
gVRUeuUpXaJu7iFZBoheQ+tSwlJNSfiH3/rNAPww8oC6svHsdfQJj724m8q2bOQa
OybujbJ1AkEA8rkLlohjtBeGWQl7JRzByhrdzeDIEKwQBcs3BvZ7XACYtV4L7V+7
wpYu+LaXglhmpHdRlqQgSyNu1oKsEDzLYQJALAy4IKY8QPzMw808R27dQ2Tuwr4y
CSvRxcoCDj3kXjylYYReFf/ToxC8qXN0v4++CKX3WtSzwc7/+3F1Q0drSQJBANye
p9LG2+FI9Lufa4hbMCX076D/bLoCu3mYscapaY1BmYxZFHxJZQ/ElKNKzEIU+g8J
yWYkfpntdgSSt7T2nWECQGx5NHgjpakZOADnm7Jk1FNd0qPfrLu9TGqBSP+qB0BQ
AoBKfQHP9F50MNJXahTzb62HfiJtJrv5bkTSATi9YXM=
-----END RSA PRIVATE KEY-----
"""

# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    key = RSA.importKey(privKey)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(session_key)
    pass


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function
    dec = AES.new(session_key, AES.MODE_ECB)
    print(dec.decrypt(client_message))
    return dec.decrypt(client_message)
    pass


# Encrypt a message using the session key
def encrypt_message(message, session_key):
    # TODO: Implement this function
    enc = AES.new(session_key, AES.MODE_ECB)
    return enc.encrypt(message)
    pass


# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:
        reader = open("../passfile.txt", 'r')
        for line in reader.read().split('\n'):
            line = line.split("\t")
            print(user.decode() == line[0])
            if line[0] == user.decode():
                # TODO: Generate the hashed password
                salt = line[1]
                print(salt)
                hashed_password = hashlib.sha256((salt + password.decode()).encode())
                print(hashed_password)
                return hashed_password == line[2]
        reader.close()
    except FileNotFoundError:
        return False
    return False

def main():
    # Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
    	while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)
                print(plaintext_key)
                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                decryptedMsg = decrypt_message(ciphertext_message, plaintext_key)
                # TODO: Split response from user into the username and password
                splitResponse = decryptedMsg.rstrip().split() #Array with user, salt, and
                                                     #hashed password in that order
                username = splitResponse[0]
                pwd = splitResponse[1]
                print(username)
                print(pwd)
                userExists = verify_hash(username, pwd)
                response = ""
                if(userExists):
                    response = "authenticated"
                else:
                    response = "denied"
                # TODO: Encrypt response to client
                encr = AES.new(plaintext_key, AES.MODE_ECB)
                ciphertext_response = encr.encrypt(pad_message(response))
                # Send encrypted response
                send_message(connection, ciphertext_response)
            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()


if __name__ in "__main__":
    main()
