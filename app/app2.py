#sudo pip3 install flask => to install outside the local directory, must include sudo
from flask import Flask, request, jsonify
from colorama import Fore, Style
from pprint import pprint
from flask_cors import CORS
import os

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app, resources={r"/*": {"origins": ["*"]}})

@app.route('/docker-restore', methods=['POST'])
def docker():

    if request.method == 'POST':
        content = request.json

        original_filepath = content["dockerfile"]["path"]
        backup_filepath = content["dockerfile"]["path"] + ".bak"

        print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
        os.remove(original_filepath)
        os.rename(backup_filepath,backup_filepath)
     
        print(f"{Fore.GREEN}# Removing original file {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# Backup restored :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        return {"dockerfile":True}

@app.route('/compose-restore', methods=['POST'])
def compose():

    if request.method == 'POST':
        
        content = request.json

        original_filepath = content["composefile"]["path"]
        backup_filepath = content["composefile"]["path"] + ".bak"

        print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
        os.remove(original_filepath)
        os.rename(backup_filepath,backup_filepath)
     
        print(f"{Fore.GREEN}# Removing original file {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# Backup restored :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        return {"composefile":True}

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5002, debug=False)    