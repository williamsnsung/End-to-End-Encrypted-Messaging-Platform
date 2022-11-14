from flask import (
    Blueprint, request, make_response, jsonify
)   

from db import get_db, getStorablePassword, verifyPassword
import logging

bp = Blueprint('auth', __name__, url_prefix='/auth')
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')

@bp.route('/register', methods = ('GET','POST'))
def register():
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
                password, salt = getStorablePassword(password.encode('latin1'))
                logging.info(f"Inserting into the database the following user and password")
                logging.info(f"username: {username}")
                logging.info(f"derived password key: {password}")
                db.execute(
                    "INSERT INTO user (username, password, public_key, salt) VALUES (?, ?, ?, ?)",
                    (username, password, publicKey, salt),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
        if error is not None:
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res

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
                password = getStorablePassword(password.encode('latin1'))
                logging.info(f"Deleting the following user from the database")
                logging.info(f"username: {username}")
                db.execute(
                    "DELETE FROM user WHERE username = ?",
                    (username,)
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} does not exist."
        if error is not None:
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res



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

        error = verifyUser(username, password, db)

        if error is None:
            try:
                logging.info(f"User {username} succesfully found")
                logging.info(f"Updating the public key for {username}")
                db.execute(
                    "UPDATE user SET public_key = ? WHERE username = ?",
                    (publicKey, username),
                )
                logging.info(f"Updated public key of {username} to:\n {publicKey}")
                db.commit()
            except db.IntegrityError:
                error = f"Could not update the public key for {username}"
        if error is not None:
            logging.error(f"Error: {error}")
            res = make_response(jsonify({'message' : error}), 403)
    return res

def verifyUser(username, password, db):
    error = None
    logging.info(f"Looking up in database user: {username}")
    user = db.execute(
        'SELECT * FROM user WHERE username = ?', (username,)
    ).fetchone()
    if user is None:
        error = 'Incorrect username or password.'
    else:
        res = verifyPassword(
            password.encode('latin1'), 
            user['salt'].encode('latin1'), 
            user['password'].encode('latin1')
        )
        if res == False:
            error = 'Incorrect username or password.'
    return error

# @bp.before_app_request
# def load_logged_in_iser():
#     user_id = session.get('user_id')

#     if user_id is None:
#         g.user = None
#     else:
#         g.user = get_db().execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()

# @bp.route('/logout')
# def logout():
#     session.clear()
#     return redirect(url_for('index'))

# def login_required(view):
#     @functools.wraps(view)
#     def wrapped_view(**kwargs):
#         if g.user is None:
#             return redirect(url_for('auth.login'))
#         return view(**kwargs)

#     return wrapped_view
