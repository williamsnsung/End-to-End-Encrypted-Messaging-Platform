from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

import socket
import ssl
import requests

keyFile = "./key.pem"

class Client:
    def __init__ (self, username, sessionKey):
        self.username = username
        self.sessionKey = sessionKey
        self.oneTimeKey = self.generateRSAKey()

    def generateRSAKey(self):
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        return key

    def getSignature(self, messageBinary):
        signature = self.sessionKey.sign(
            messageBinary,
                padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature


    def verifyMessage(self, message, signature):
        pass

    def decrypt(self, cipherText, privateKey):
        plainText = privateKey.decrypt(
            cipherText,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plainText

    def encrypt(self, messageBinary, publicKey):
        cipherText = publicKey.encrypt(
            messageBinary,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return cipherText

    def startup():
        username = ""
        password = ""
        sessionKey = Client.generateRSAKey()
        print("Welcome to C02: The Message")
        print("Would you like to [L]ogin or [R]egister an account?")
        uIn = input("$ ")
        while uIn not in "lLrR":
            print("Please enter either [L] or [l] to login or [R] or [r] to register an account")
            uIn = input("$ ")
        if uIn in "lL":
            print("Username:")
            username = input("$ ")
            print("Password:")
            password = input("$ ")
        else:
            print("Username:")
            username = input("$ ")
            print("Password:")
            password = input("$ ")
            print("Confirm:")
            confirm = input("$ ")
            while password != confirm:
                print("Passwords do not match, please re-enter your password")
                print("Password:")
                password = input("$ ")
                print("Confirm:")
                confirm = input("$ ")
        


uIn = ""
startup = True
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# # uses the server created cert as the certification authority to verify against
# context.load_verify_locations("../server/cert.pem")
# # using the context to connect to a server validates the certificate and the hostname below
# conn = context.wrap_socket(socket.socket(socket.AF_INET),
#                            server_hostname="https://127.0.0.1")

# # attempts to connect to the server whilst checking the certificate is valid with specified certificate authority
# conn.connect(("127.0.0.1", 5000))
# conn.close()

url = u"https://127.0.0.1:5000/hello"
x = requests.get(url, verify='../server/cert.pem')
print(x)

# while uIn != ":quit" or ":q":
#     if startup:
#         Client.startup()
#         startup = False