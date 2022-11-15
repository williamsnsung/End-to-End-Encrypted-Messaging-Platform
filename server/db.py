import sqlite3
import click
import os
from flask import current_app, g

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey, InvalidSignature

from pathlib import Path
import datetime
import ipaddress

# paths to the key and certificate
keyFile = "./key.pem"
certFile = "./cert.pem"
# the passphrase used on the private key for generation and loading
password = b"passphrase"

# return the current instance of the database
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

# close the current instance of the database
def close_db(e=None):
    db = g.pop('db', None)
    
    if db is not None:
        db.close()

# initialise the database
def init_db():
    db = get_db()
    
    with current_app.open_resource('schema.sql') as f:
        db.executescript(f.read().decode('utf8'))


@click.command('init-db')

def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialised the databse.')
    
def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)

# generates an rsa key using the password provided
def generateRSAKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(keyFile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(password),
        ))

# generates a self signed certificate
def generateSelfSignedCert(key):
    if not Path(certFile).is_file():
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Scotland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"St Andrews"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of St Andrews")
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            # Our certificate will be valid for 365 days
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.IPv4Address('127.0.0.1'))]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open(certFile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

# serialises the private key and generates it if it doesn't exist
def getRSAPrivateKey():
    if not Path(keyFile).is_file():
        generateRSAKey()
    privateKeyFile = open(keyFile, "rb")
    data = privateKeyFile.read()
    privateKeyFile.close()
    return serialization.load_pem_private_key(data, password, True)

# verifies that a message is from the user by using the provided signature and the public key on the database
def verifyMessageSignature(messageBinary, signatureBinary, username):
    db = get_db()
    error = None
    user = None

    # tries to retrieve the public key on the database
    if error is None:
        try:
            user = db.execute(
                'SELECT public_key FROM user WHERE username = ?', (username,)
            ).fetchone()
            if user is None:
                error = 'Incorrect username.'
        except db.IntegrityError:
            error = f"User {username} does not exist."

    # read the public key into a usable format
    publicKey = serialization.load_pem_public_key(
        user['public_key'].encode('latin1')
    )

    # verify authenticity of the provided signature
    try:
        publicKey.verify(
            signatureBinary,
            messageBinary,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True

# uses the scrypt key derivation algorithm to encode the password so that it may be stored on the database
# returns the salt used and the resultant key
def getStorablePassword(passwordBytes):
    salt = os.urandom(16)
    # derive
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    salt = salt.decode('latin1')
    key = kdf.derive(passwordBytes).decode('latin1')
    return key, salt

# verifies a password against the derived key stored on the database
def verifyPassword(passwordBytes, saltBytes, derivedPasswordBytes):
    kdf = Scrypt(
        salt=saltBytes,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    try:
        kdf.verify(passwordBytes, derivedPasswordBytes)
    except InvalidKey:
        return False
    return True