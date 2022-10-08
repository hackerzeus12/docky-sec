#!/bin/bash
chmod +x -R .
apt-get update
apt install python3
apt install python3-pip
pip3 install virtualenv
virtualenv venv
source venv/bin/activate
pip3 install -r requirements.txt
deactivate
