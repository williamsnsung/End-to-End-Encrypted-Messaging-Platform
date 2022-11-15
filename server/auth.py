from flask import (
    Blueprint, request, make_response, jsonify
)   

from db import get_db, getStorablePassword, verifyPassword
import logging

logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')

bp = Blueprint('auth', __name__, url_prefix='/auth')

# registers a user to the website if the user doesn't exist 
@bp.route('/register', methods = ('GET','POST'))
def register():
    # defaults to 200
    res = make_response()
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        publicKey = request.form['publicKey']
        logging.info("Registration request received")
        logging.info(f"Request contents: {request.form}")

        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not publicKey:
            error = 'Public key is required.'

        if error is None:
            try:
                # use a kdf to derive a key in place of the hashed password
                password, salt = getStorablePassword(password.encode('latin1'))
                logging.info(f"Inserting into the database the following user and password")
                logging.info(f"username: {username}")
                logging.info(f"derived password key: {password}")
                db.execute(
                    "INSERT INTO user (username, password, public_key, salt) VALUES (?, ?, ?, ?)",
                    (username, password, publicKey, salt),
                )
                db.commit()
                logging.info(f"Succesfully registed : {username}")
            except db.IntegrityError:
                # create an error message if the user already exists
                error = f"User {username} is already registered."
        # if there is an error, return 403 along with the message
        if error is not None:
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res

# deletes a user from the database after verifying the password given with what is on the database
@bp.route('/delete', methods = ('GET','POST'))
def delete():
    res = make_response()
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        logging.info("Delete request received")
        logging.info(f"Request contents: {request.form}")

        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        error = verifyUser(username, password, db)

        if error is None:
            try:
                logging.info(f"User password verified")
                logging.info(f"Deleting the following user from the database")
                logging.info(f"username: {username}")
                db.execute(
                    "DELETE FROM user WHERE username = ?",
                    (username,)
                )
                db.commit()
                logging.info(f"Succesfully deleted: {username}")
            except db.IntegrityError:
                # if the user doesn't exist on the database then throw an error
                error = f"User {username} does not exist."
        if error is not None:
            # if there is an error then status code 403 forbidden + message
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res

# logs in a user after verifying their password, updates the public key on the database to the one used by the current session of the client
@bp.route('/login', methods = ('GET', 'POST'))
def login():
    res = make_response()
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']
        publicKey = request.form['publicKey']
        logging.info("Login request received")
        logging.info(f"Request contents: {request.form}")

        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not publicKey:
            error = 'Public key is required.'

        # verify the users password on the database
        error = verifyUser(username, password, db)

        if error is None:
            try:
                # if password is valid then update their public key on the database
                logging.info(f"User <{username}> validated")
                logging.info(f"Updating the public key for <{username}>")
                db.execute(
                    "UPDATE user SET public_key = ? WHERE username = ?",
                    (publicKey, username),
                )
                logging.info(f"Updated public key of <{username}> to:\n {publicKey}")
                logging.info(f"Successfully logged in: {username}")
                db.commit()
            except db.IntegrityError:
                # error message if the key could not be updated for some reason
                error = f"Could not update the public key for {username}"
        if error is not None:
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res

# function which verifies a user password with what is on the database
def verifyUser(username, password, db):
    error = None
    # looks up the user in the database, sees if they exist, if they don't then error
    logging.info(f"Looking up in database user: {username}")
    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()
    if user is None:
        error = 'Incorrect username or password.'
    else:
        # verify their password, return None if the password is valid
        res = verifyPassword(
            password.encode('latin1'), 
            user['salt'].encode('latin1'), 
            user['password'].encode('latin1')
        )
        if res == False:
            error = 'Incorrect username or password.'
        else:
            logging.info(f"Correct password provided for: {username}")
    return error
