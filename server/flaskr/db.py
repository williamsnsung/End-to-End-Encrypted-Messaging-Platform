import sqlite3
import click
from flask import current_app, g

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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

def getRSAKey():
    if not Path(keyFile).is_file():
        generateRSAKey()
    privateKeyFile = open(keyFile, "rb")
    data = privateKeyFile.read()
    privateKeyFile.close()
    return cryptography.hazmat.primitives.serialization.load_pem_private_key(data, None, True)

def generate_certificate(user):
    key = getRSAKey()

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"UK"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"St Andrews"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"University of St Andrews"),
        x509.NameAttribute(NameOID.USER_ID, u"University of St Andrews")
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
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256())
    
    return cert

def verify_certificate(toVerify):
    pass

