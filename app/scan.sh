#!/bin/bash
pip3 install virtualenv
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
export FLASK_APP=app/app3.py
flask run --host=0.0.0.0 --port=5002
deactivate
