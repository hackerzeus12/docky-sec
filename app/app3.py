#sudo pip3 install flask => to install outside the local directory, must include sudo
from flask import Flask, request, jsonify
from colorama import Fore, Style
from pprint import pprint
from flask_cors import CORS
import os
from subprocess import call

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app, resources={r"/*": {"origins": ["*"]}})

@app.route('/scan', methods=['POST'])
def scan():

    #  curl -X POST http://127.0.0.1:5000/ -H 'Content-Type: application/json' -d '{"dockerfile":{ "fixedVersion":"latest","path":"/home/dush/dockersec/cis/samples/Dockerfile","version":"latest","image":"vulhub/node" }}'
    if request.method == 'POST':
        content = request.json

        docker_filepath = content["docker"]
        compose_filepath = content["compose"]

        cmd = "python3 main.py scan --scantype=host --dockerfile=" + docker_filepath + "--composefile=" + compose_filepath

        print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
        print(f"{Fore.GREEN}# Running Scan {Style.RESET_ALL}")
        rc = call(cmd, shell=True)

        print(f"{Fore.GREEN}# Scan Finished :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        return {"scan":True}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5002, debug=False)    