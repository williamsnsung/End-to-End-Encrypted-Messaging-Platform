Steps to run:

Create a virtual environment:
	python3 -m venv ./venv  
Activate it:
	source venv/bin/activate	
Install the following:
	pip install Flask
	pip install cryptography
	pip install eventlet
	pip install Flask-SocketIO
	pip install requests
	pip install python-socketio
Run the flask application:
   	python3 server/__init__.py
Run the client application:
   	python3 client/client.py
Run multiple client applications in seperate windows to increase user count on the server
