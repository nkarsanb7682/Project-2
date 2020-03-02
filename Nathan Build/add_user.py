import hashlib
import os

user = raw_input("Enter a username: ")
password = raw_input("Enter a password: ")

# TODO: Create a salt and hash the password

#Creates salt 32 bytes long
salt = os.urandom(32)
#Hash password with salt
hashed_password = hashlib.sha256((str(salt) + password).encode("utf-8"))

try:
    reading = open("passfile.txt", 'r')
    for line in reading.read().split('\n'):
        if line.split('\t')[0] == user:
            print("User already exists!")
            exit(1)
    reading.close()
except FileNotFoundError:
    pass

with open("passfile.txt", 'a+') as writer:
    writer.write("{0}\t{1}\t{2}\n".format(user, salt, hashed_password))
    print("User successfully added!")
