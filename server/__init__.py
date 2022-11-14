import os
from flask import Flask
import db
import auth
import logging

# create and configure the app
app = Flask(__name__, instance_relative_config=True)
# https://www.askpython.com/python-modules/flask/flask-logging
logging.basicConfig(filename='record.log', level=logging.DEBUG, format=f'%(asctime)s %(levelname)s %(filename)s %(funcName)s : %(message)s')
logging.info("========== STARTING SERVER ==========")
app.config.from_mapping(
    SECRET_KEY='dev',
    DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
)

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

# from . import blog
# app.register_blueprint(blog.bp)
# app.add_url_rule('/', endpoint = 'index')

if __name__ == "__main__":
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))