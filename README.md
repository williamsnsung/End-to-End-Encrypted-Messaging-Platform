Steps to run:

Create a virtual environment:
	python3 -m venv ./venv  
Activate it:
	source venv/bin/activate	
Install Flask:
	pip install Flask
Run the flask application:
   	flask --app flaskr --debug run	
Initialise the database:
	flask --app flaskr init-db
Server runs on:
    http://127.0.0.1:5000/
