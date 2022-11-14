from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

import requests
import logging
import sys
import getpass

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
        username = self.getInput()
        print("Password:")
        password = self.getInput(password=True)
        return username, password
    
    def hash(self, password):
        digest = hashes.Hash(hashes.SHA256())
        digest.update(password.encode())
        return digest.finalize().decode('latin1')

    def serializePublicKey(self, RSAKey):
        publicKey = RSAKey.public_key()
        publicKey = publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return publicKey.decode('latin1')

    def startup(self):
        logging.info("\n\n========== STARTING CLIENT ==========")
        loggedIn = False
        username = ""
        password = ""
        publicKey = self.serializePublicKey(self.sessionKey)
        print("Welcome to C02: The Message")
        uIn = self.intro()
        while loggedIn == False:
            if uIn in "lL":
                logging.info("Starting log in sequence")
                username, password = self.getUser()
            else:
                logging.info("Beginning registration sequence")
                username, password = self.getUser()

                print("Confirm:")
                confirm = self.getInput(password=True)

                while password != confirm:
                    print("Passwords do not match, please re-enter your password")
                    print("Password:")
                    password = self.getInput(password=True)
                    print("Confirm:")
                    confirm = self.getInput(password=True)

            logging.info(f"Username: {username}")
            password = self.hash(password)
            logging.info(f"Hashed Password: {password}")
            res = None
            if uIn in "rR":
                logging.info(f"Requesting registration of {username}")
                print("Registering...")
                res = self.authPost("register", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res is None or res.ok:
                if res is not None:
                    logging.info(f"Successfully registered: {username}")
                logging.info(f"Requesting log in of {username}")
                print("Logging in...")
                res = self.authPost("login", {'username' : username, 'password' : password, 'publicKey' : publicKey})
            if res.ok == False:
                self.logError(res)
                uIn = self.intro()
            else:
                logging.info(f"Successfully logged in: {username}")
                self.username = username
                print(f"Success, welcome: {self.username}!")
                loggedIn = True

    def deleteAccount(self):
        username = self.username
        logging.info(f"Beginning request to delete user: {username}")
        print("Please confirm your password")
        print("Password:")
        password = self.getInput(username, True)
        password = self.hash(password)
        logging.info(f"Hashed Password: {password}")
        res = self.authPost("delete", {'username' : username, 'password' : password})
        logging.info(f"Authentication request result: {res}")
        if res.ok:
            logging.info(f"Account deleted for {username}")
            print("Your account has been deleted")
            self.end()
        else:
            self.logError(res)

    def logError(self, res):
        json = res.json()
        print(f"Error: {json['message']}")
        logging.info(f"Status code: {res.status_code} Message: {json['message']}")

    def intro(self):
        uIn = ""
        while True:
            print("Would you like to [L]ogin or [R]egister an account?")
            print("\t[L]ogin")
            print("\t[R]egister")
            print("\t[E]xit")
            uIn = self.getInput()
            if uIn in "YyEeLlRr":
                break
        if uIn in "Ee":
            self.end()
        return uIn
    
    def end(self):
        print("\nExiting C02: Goodbye!")
        sys.exit()
    
    def getInput(self, preamble = "", password = False):
        uIn = ""
        if password:
            uIn = getpass.getpass(f"{preamble}$ ")
        else:
            uIn = input(f"{preamble}$ ")
        print()
        return uIn
    
    def printFreeUsers(self):
        pass

    def sendMsg(self, partner, msg):
        pass



uIn = "start"
user = ""
chatting = ""
client = Client()
client.startup()
user = client.username
while uIn not in "eE":
    if chatting == "":
        print("Commands:")
        print("\t[F]ree users")
        print("\t[C]hat with online <USER>")
        print("\t[D]elete account")
        print("\t[E]xit")
    uIn = client.getInput(user)
    
    if chatting == "":
        if uIn[0] in "cC":
            partner = uIn[2:]
            print(f"You are now chatting with: {partner}")
            print(f"To stop chatting, type: !exit")
            chatting = partner
        elif uIn in "fF":
            client.printFreeUsers()
        elif uIn in "dD":
            client.deleteAccount()
        elif uIn in "eE":
            client.end()
    elif uIn == "!exit":
        chatting = ""
    else:
        client.sendMsg(partner, uIn)
