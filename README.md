This software runs on localhost using port 5000, so make sure that one is free!
Implemented in Python 3.8.10

Steps to run:

Create a virtual environment (Though one is provided!):
	python3 -m venv ./venv  
Activate it:
	source venv/bin/activate	
Install the following (If you created your own virtual environment/pip list is magically empty):
	pip install Flask
	pip install cryptography
	pip install eventlet
	pip install Flask-SocketIO
	pip install requests
	pip install python-socketio
Run the flask application:
   	python3 server/__init__.py
		This will prompt you for a PEM passphrase, being: "passphrase", excluding the speech marks
Run the client application (in a seperate shell!):
   	python3 client/client.py
		There shouldn't be any users in the provided database instance, however if you encounter an error during registration, chances are that is an existing user
	
Notes:
	Run multiple client applications in seperate shells to increase user count on the server
	You can chat with yourself, but you can also chat with other users
	Sometimes you get an error message before an input, you most likely can just continue typing commands, but if not CTRL + C to kill the program and restart it
	The client and server directories don't currently have logs in them, but when you run them they will appear