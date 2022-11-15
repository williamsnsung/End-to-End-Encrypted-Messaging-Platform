import os
from flask import Flask, request
import db
import auth
import logging
from flask_socketio import SocketIO
from flask_socketio import send, emit
from db import verifyMessageSignature

# create and configure the app
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')
app = Flask(__name__, instance_relative_config=True)
# https://www.askpython.com/python-modules/flask/flask-logging
logging.info("\n\n\n\n========== STARTING SERVER ==========")
app.config.from_mapping(
    SECRET_KEY='dev',
    DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
)
socketio = SocketIO(app)

try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# a simple page that says hello
@app.route('/hello')
def hello():
    return 'Hello, World!'

db.init_app(app)
db.generateSelfSignedCert(db.getRSAPrivateKey())

app.register_blueprint(auth.bp)

clientToSID = {} 
sidToClient = {}

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

@socketio.on('disconnect')
def disconnectClient():
    sid = request.sid
    username = sidToClient[sid]
    logging.info(f"Disconnecting the following user: {username}")
    del clientToSID[username]
    del sidToClient[sid]
    logging.info(f"Disconnected session for user {username}")

@socketio.on('init msg')
def initMsg(json):
    print(request.sid)
    print(json)
    #{'source': client.username, 'target' : partner, 'signature' : client.getSignature(partner)}
    source = json['source']
    target = json['target']
    signature = json['signature']
    if source in clientToSID and target in clientToSID:
        if verifyMessageSignature(target.encode('latin1'), signature.encode('latin1'), source):
            targetData = db.get_db().execute(
                'SELECT public_key FROM user WHERE username = ?', 
                (target,)
            ).fetchone()
            emit('target public key', {'public key': targetData['public_key'], 'target': target})
        else:
            emit('bad key', {'message': 'Invalid signature.'})
    else:
        emit('busy user', {'message': 'Target user is unavailable.'})
    # receive source user, target user, signature
    # check both users in dictionary of logged in users
    # use signature to verify that the request is from source user
    # return public key of target user encrypted using public key of source user signed by server

@socketio.on('send message')
def sendMsg(json):
    # receive source user, encrypted symmetric key, message encrypted by symmetric key, signature, target user
    # check both users are still online
    # verify source user signature
    # forward data to target user
    pass

if __name__ == "__main__":
    # ssl_context=('cert.pem', 'key.pem')
    socketio.run(app, debug=True, keyfile='key.pem', certfile='cert.pem')