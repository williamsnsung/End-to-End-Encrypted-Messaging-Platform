from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import requests
import logging
import sys

logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')
keyFile = "./key.pem"
url = "https://127.0.0.1:5000/"
class Client:
    def __init__ (self):
        self.username = ""
        self.sessionKey = self.generateRSAKey()
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

    def authPost(self, path, json):
        return requests.post(url + "/auth/" + path, data=json, verify="../server/cert.pem")

    def getUser(self):
        print("Username:")
        username = input("$ ")
        print("Password:")
        password = input("$ ")
        return username, password
    
    def hash(self, password):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        return digest.finalize().decode('latin1')

    def serializePublicKey(self):
        publicKey = self.sessionKey.public_key()
        publicKey = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return publicKey.decode('latin1')

    def startup(self):
        logging.info("========== STARTING CLIENT ==========")
        loggedIn = False
        username = ""
        password = ""
        publicKey = self.serializePublicKey()
        print("Welcome to C02: The Message")
        print("Would you like to [L]ogin or [R]egister an account?")
        uIn = input("$ ")
        while uIn not in "lLrR":
            print("Please enter either [L] or [l] to login or [R] or [r] to register an account")
            uIn = input("$ ")
        while loggedIn == False:
            if uIn in "lL":
                logging.info("Starting log in sequence")
                username, password = self.getUser()
            else:
                logging.info("Beginning registration sequence")
                username, password = self.getUser()

                print("Confirm:")
                confirm = input("$ ")

                while password != confirm:
                    print("Passwords do not match, please re-enter your password")
                    print("Password:")
                    password = input("$ ")
                    print("Confirm:")
                    confirm = input("$ ")

            logging.info(f"Username: {username}")
            password = self.hash(password)
            logging.info(f"Hashed Password: {password}")
            res = None
            if uIn in "rR":
                logging.info(f"Requesting registration of {username}")
                print("Registering...")
                res = self.authPost("register", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res is None or res.ok:
                logging.info(f"Requesting log in of {username}")
                print("Logging in...")
                res = self.authPost("login", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res.ok == False:
                json = res.json()
                print(f"Error: {json['message']}")
                logging.info(f"Status code: {res.status_code} Message: {json['message']}")
                while True:
                    print("Would you like to [L]ogin or [R]egister an account?")
                    print("\t[L]ogin")
                    print("\t[R]egister")
                    print("\t[E]xit")
                    uIn = input("$ ")
                    if uIn in "YyEeLlRr":
                        break
                if uIn in "Ee":
                    sys.exit()
                
                
            else:
                print("Success!")
                loggedIn = True

    def deleteAccount(self, username):
        logging.info(f"Beginning request to delete user: {username}")
        print("Please confirm your password")
        print("Password:")
        password = input(f"{username}$ ")
        password = self.hash(password)
        logging.info(f"Hashed Password: {password}")
        res = self.authPost("delete", {'username' : username, 'password' : password})
        logging.info(f"Authentication request result: {res}")



uIn = ""
client = Client()
client.startup()
# client.deleteAccount("test")