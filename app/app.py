#sudo pip3 install flask => to install outside the local directory, must include sudo
from flask import Flask, request, jsonify
from dockerfile_parse import DockerfileParser
from colorama import Fore, Style
from pprint import pprint
from flask_cors import CORS
import os

app = Flask(__name__)
app.config['CORS_HEADERS'] = 'Content-Type'
cors = CORS(app, resources={r"/*": {"origins": ["*"]}})

@app.route('/docker', methods=['POST'])
def dockerFixer():

    #  curl -X POST http://127.0.0.1:5000/ -H 'Content-Type: application/json' -d '{"dockerfile":{ "fixedVersion":"latest","path":"/home/dush/dockersec/cis/samples/Dockerfile","version":"latest","image":"vulhub/node" }}'
    if request.method == 'POST':
        # modify docker file
        content = request.json

        dfp = DockerfileParser()

        original_filepath = content["dockerfile"]["path"]

        # open dockerfile for read
        print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        with open(content["dockerfile"]["path"], 'r+') as f1:
            data = f1.read()
            dfp.content = data
            # pprint(dfp.content)

            # creating backup file for write 
            backup_filepath = content["dockerfile"]["path"] + ".bak"

            print(f"{Fore.YELLOW}[DEBUG] Creating backup file on {backup_filepath} {Style.RESET_ALL}")

            with open(backup_filepath, 'w') as f2:
                f2.seek(0)
                f2.truncate() 
                f2.write(data)

            # writing data to original file
            print(f"{Fore.YELLOW}[DEBUG] Writing data to original file on {original_filepath} {Style.RESET_ALL}")

            if dfp.baseimage is not None:
                dfp.baseimage = content["dockerfile"]["image"] + ":" + content["dockerfile"]["fixedVersion"]
            f1.seek(0)
            f1.truncate()    
            f1.write(dfp.content)   
        
        print(f"{Fore.GREEN}# Congratulations :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# You may close the web server now :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        return {"dockerfile":True}

@app.route('/compose', methods=['POST'])
def composeFixer():

    #  curl -X POST http://127.0.0.1:5000/ -H 'Content-Type: application/json' -d '{"dockerfile":{ "fixedVersion":"latest","path":"/home/dush/dockersec/cis/samples/Dockerfile","version":"latest","image":"vulhub/node" }}'
    if request.method == 'POST':
        # modify docker file
        content = request.json
        # print(content["dockerfile"]["path"])

        dfp = DockerfileParser()

        # modify composefile
        original_filepath = content["composefile"]["path"]
        with open(content["composefile"]["path"], 'r+') as f3:
            data = f3.read()
            dfp.content = data
            a = dfp.structure        

            # creating backup file for write 
            backup_filepath = content["composefile"]["path"] + ".bak"

            print(f"{Fore.YELLOW}[DEBUG] Creating backup file on {backup_filepath} {Style.RESET_ALL}")

            with open(backup_filepath, 'w') as f4:
                f4.seek(0)
                f4.truncate() 
                f4.write(data) 

        # writing data to original file
        print(f"{Fore.YELLOW}#[DEBUG] Writing data to original file on {original_filepath} {Style.RESET_ALL}")

        with open(content["composefile"]["path"], 'r+') as f5:    
            data = f5.read()
            dfp.content = data
            a = dfp.structure      
            
            for line in a:
                if line['instruction'] == 'IMAGE:':
                    # print(line['content'].split(":"))
                    baseImage = line['content']   
                    ins = baseImage.split(":")[0] + ":"
                    image = baseImage.split(":")[1]
                    latest = ":latest\n"
                    new = ins + image + latest
                    # print(new)
                    line['content'] = new
                    # print(line['content'])
                    # f5.write(line['content'])
                # f3.write(line['content'])

            f5.seek(0)
            f5.truncate() 

            for line in a:
                f5.write(line['content'])    
        
        print(f"{Fore.GREEN}# Congratulations :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# You may close the web server now :) {Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        return {"composefile":True}        

@app.route('/docker-restore', methods=['POST'])
def dockerRestore():

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
def composeRestore():

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
    app.run(host='0.0.0.0', port=5001, debug=False)    