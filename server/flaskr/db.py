import sqlite3
import click
from flask import current_app, g

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID

from pathlib import Path
import datetime

keyFile = "./key.pem"
certFile = "./certificate.pem"

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(
            current_app.config['DATABASE'],
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row

    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    
    if db is not None:
        db.close()

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

# Generates a private key if one doesn't exist locally and stores it in ./key.pem
# TODO encrypt private key
def generateRSAKey():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(keyFile, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(b"passphrase"),
        ))

def generateSelfSignedCert(key):
    if not Path(certFile).is_file():
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Scotland"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"St Andrews"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of St Andrews"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"127.0.0.1"),
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
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False,
        # Sign our certificate with our private key
        ).sign(key, hashes.SHA256())
        # Write our certificate out to disk.
        with open(certFile, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

def getRSAPrivateKey():
    if not Path(keyFile).is_file():
        generateRSAKey()
    privateKeyFile = open(keyFile, "rb")
    data = privateKeyFile.read()
    privateKeyFile.close()
    return serialization.load_pem_private_key(data, None, True)

def getRSAPublicKey():
    if not Path(keyFile).is_file():
        generateRSAKey()
    privateKeyFile = open(keyFile, "rb")
    data = privateKeyFile.read()
    privateKeyFile.close()
    return serialization.load_pem_public_key(data, None, True)

def getSignature(messageBinary):
    privateKey = getRSAPrivateKey()
    signature = privateKey.sign(
        messageBinary,
            padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verifyMessage(message, signature, username):
    db = get_db()
    error = None
    # Get public key binary from db
    user = db.execute(
        'SELECT public_key FROM user WHERE username = ?', (username,)
    ).fetchone()

    if user is None:
        error = 'Incorrect username.'
    # read the binary into a usable format
    publicKey = serialization.load_pem_public_key(
        bytes(user['public_key'])
    )

    publicKey.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

def decrypt(cipherText):
    privateKey = getRSAPrivateKey()
    plainText = privateKey.decrypt(
        cipherText,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plainText

def encrypt(messageBinary, publicKey):
    cipherText = publicKey.encrypt(
        messageBinary,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipherText