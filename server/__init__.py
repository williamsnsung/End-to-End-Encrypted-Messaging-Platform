import os
from flask import Flask, request
import db
import auth
import logging
from flask_socketio import SocketIO
from flask_socketio import emit
from db import verifyMessageSignature
import secrets

# create and configure the app
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')
app = Flask(__name__, instance_relative_config=True)
logging.info("\n\n\n\n========== STARTING SERVER ==========")
app.config.from_mapping(
    # generate a random secret key for encoding the sessions
    SECRET_KEY=secrets.token_hex(),
    # connect with the database instance given
    DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
)
socketio = SocketIO(app)

try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# connect to the database and generate a key and certificate if they don't already exist
db.init_app(app)
key = db.getRSAPrivateKey()
db.generateSelfSignedCert(key)

# add the paths defined in the db file to be reachable
app.register_blueprint(auth.bp)

# mappings from a client username to their session and vice versa, contains active clients only
clientToSID = {} 
sidToClient = {}

# when a user connects to via a socket, verify their identity using the public key given on login
# if legal then add them to the mapping above, otherwise disconnect them from the server
@socketio.on('connect')
def connectClient(auth):
    username = auth['username']
    sid = request.sid
    logging.info(f"Attempting to connect the following user to the server socket")
    logging.info(f"Username: {username}")
    logging.info(f"session id: {sid}")
    if verifyMessageSignature(username.encode('latin1'), auth['signature'].encode('latin1'), username) == False:
        logging.info(f"Invalid signature provided by user: {username}")
        logging.info(f"Closing socket connection with user: {username}")
        emit('bad key', {'message': 'Invalid signature.'})
    logging.info(f"Valid signature provided by user: {username}")
    logging.info(f"Adding user session to active sessions: {username}")
    clientToSID[username] = sid
    sidToClient[sid] = username
    logging.info(f"Active sessions updates to the following:")
    logging.info(f"Active sessions: {clientToSID}")

# upon a user disconnecting, remove them from the above mapping and removing their public key
@socketio.on('disconnect')
def disconnectClient():
    sid = request.sid
    username = sidToClient[sid]
    logging.info(f"Disconnecting the following user: {username}")
    del clientToSID[username]
    del sidToClient[sid]
    logging.info(f"Updating the public key for <{username}>")
    db.get_db().execute(
        "UPDATE user SET public_key = NULL WHERE username = ?",
        (username,),
    )
    logging.info(f"Updated public key of <{username}> to NULL")
    logging.info(f"Disconnected session for user {username}")

# when a user begins a chat with another user, pass the target public key to the source user if the source user has a valid identity and they are both online
@socketio.on('init msg')
def initMsg(json):
    source = json['source']
    target = json['target']
    signature = json['signature']
    logging.info(f"Message initiated by user <{source}> to user <{target}>")
    # checking both users are online
    if source in clientToSID and target in clientToSID:
        logging.info(f"Both users verified to be online")
        # checking signature of source user
        if verifyMessageSignature(target.encode('latin1'), signature.encode('latin1'), source):
            logging.info(f"User <{source}> signature verified")
            targetData = db.get_db().execute(
                'SELECT public_key FROM user WHERE username = ?', 
                (target,)
            ).fetchone()
            logging.info(f"Public key of User <{target}> fetched")
            logging.info(f"Sending public key to user <{source}>")
            # sending public key after user has been verified
            emit('target public key', {'public key': targetData['public_key'], 'target': target})
        else:
            # sending error due to public key signature mismatch
            logging.error(f"Given signature does not match public key of user <{source}>")
            emit('bad key', {'message': 'Invalid signature.'})
    else:
        # sending error due to target user being offline
        logging.info(f"Target user <{target}> is offline")
        emit('busy user', {'message': 'Target user is unavailable.'})

# when a user wants to send a message to another client, verify their identity using the provided signature and check both users are online
@socketio.on('send message')
def sendMessage(json):
    source = json['source']
    target = json['target']
    symKey = json['symKey']
    message = json['message']
    signature = json['signature']
    logging.info(f"Sending message from user <{source}> to user <{target}>")
    # check both users are online
    if source in clientToSID and target in clientToSID:
        logging.info(f"Both users verified to be online")
        # verify signature from source client using their public on the database
        if verifyMessageSignature(symKey.encode('latin1'), signature.encode('latin1'), source):
            logging.info(f"User <{source}> signature verified")
            logging.info(f"Sending message to user <{target}>")
            # forward the message contents over to the client
            emit('encrypted message', {'source': source, 'message': message, 'symKey' : symKey},to=clientToSID[target])
        else:
            # if the signature doesn't match the public key stored then send back an error
            logging.error(f"Given signature does not match public key of user <{source}>")
            emit('bad key', {'message': 'Invalid signature.'})
    else:
        # if the target is offline send back an error
        logging.error(f"Target user <{target}> is offline")
        emit('busy user', {'message': 'Target user is unavailable.'})

# start up the server with the given key file and certificiation (self signed)
if __name__ == "__main__":
    socketio.run(app, debug=True, keyfile='key.pem', certfile='cert.pem')