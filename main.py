from time import clock_getres
import requests
import click
import json
import os
import nmap
from shutil import which
from pprint import pprint
from subprocess import call, DEVNULL
from bs4 import BeautifulSoup
from dockerfile_parse import DockerfileParser
import subprocess
from colorama import Fore, Style
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from requests import get

def cis_check():
    #cleaning files
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker CIS bechmarks check{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for dozens of common best-practices around deploying Docker containers in production.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Based on the CIS Docker Benchmark 1.3.1{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

    rc = call("./main.sh", shell=True)

def host_scan():
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker Host Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in host.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Running Port Scanner{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] This will take some time....{Style.RESET_ALL}")
    
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1')

    results = []

    if "tcp" in nm['127.0.0.1']:
        for port in nm['127.0.0.1']['tcp'].items():
            result = {
                "port" : port[0],
                "details": port[1],
            }

            results.append(result)
    
    # print(results)
    print(f"{Fore.YELLOW}[DEBUG] Found {len(results)} open ports{Style.RESET_ALL}")

    logdata = {}

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    logdata["hostscan"] = results

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

def scanDockerFile(dockerfile):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Docker File Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in DockerFile.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Scanning DockerFile{Style.RESET_ALL}")
    
    if os.path.exists(dockerfile):
        path = os.path.abspath(dockerfile)

        print(f"{Fore.YELLOW}[DEBUG] DockerFile found at {path}{Style.RESET_ALL}")
        dfp = DockerfileParser()

        #open file for reading
        print(f"{Fore.YELLOW}[DEBUG] Scanning DockerFile{Style.RESET_ALL}")
        with open(dockerfile, 'r') as f:
            data = f.read()
            dfp.content = data
            # pprint(dfp.content)

        if dfp.baseimage is not None:
            baseimage = dfp.baseimage.split(":")

            image = baseimage[0].strip()
            version = baseimage[1].strip()

            print(f"{Fore.YELLOW}[DEBUG] Found baseimage {image} : {version}{Style.RESET_ALL}")

            logdata = {}

            with open("results/output.log.json","r") as logfile:
                logdata = json.load(logfile)

            d = {
                "path": path,
                "location": dockerfile,
                "baseimage": baseimage,
                "image": image,
                "version":version
            }

            logdata["dockerfile"] = d

            with open("results/output.log.json","w") as logfile:
                print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
                json.dump(logdata, logfile, ensure_ascii=False, indent=4)
        else:
            (f"{Fore.YELLOW}[DEBUG] No baseimage found{Style.RESET_ALL}")    
    else:
        print(f"{Fore.YELLOW}[DEBUG] DockerFile not found{Style.RESET_ALL}")

def scanComposeFile(composefile):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Composefile File Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for security vulenerabilities in Composefile.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[DEBUG] Scanning Composefile{Style.RESET_ALL}")
    
    if os.path.exists(composefile):
        path = os.path.abspath(composefile)

        print(f"{Fore.YELLOW}[DEBUG] Composefile found at {path}{Style.RESET_ALL}")
        dfp = DockerfileParser(False)

        # open file for reading
        print(f"{Fore.YELLOW}[DEBUG] Scanning Composefile{Style.RESET_ALL}")
        with open(composefile, 'r') as f:
            data = f.read()
            dfp.content = data
            a = dfp.structure        

            for line in a:
                if line['instruction'] == 'IMAGE:':
                    # print(line['content'].split(":"))
                    baseImage = line['content'].split(":")[1:3] 

                    image = baseImage[0].strip()
                    version = baseImage[1].strip()

                    print(f"{Fore.YELLOW}[DEBUG] Found baseimage {image} : {version}{Style.RESET_ALL}")

                    logdata = {}

                    with open("results/output.log.json","r") as logfile:
                        logdata = json.load(logfile)

                    d = {
                        "path": path,
                        "location": composefile,
                        "baseimage": baseImage,
                        "image": image,
                        "version":version,
                    }

                    logdata["composefile"] = d

                    with open("results/output.log.json","w") as logfile:
                        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
                        json.dump(logdata, logfile, ensure_ascii=False, indent=4)
        
    else:
        print(f"{Fore.YELLOW}[DEBUG] Composefile not found{Style.RESET_ALL}")


def finish(scanId):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Finishing Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for system information.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    
    logdata = {}

    info = subprocess.run(['lsb_release', '-a'], capture_output=True, text=True).stdout
    
    ip = get('https://api.ipify.org').content.decode('utf8')
    print(f"{Fore.YELLOW}[DEBUG] Public IP address is: {ip}{Style.RESET_ALL}")

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    d = {
        "scanId": str(scanId),
        "info": str(info),
        "ip": str(ip),
    }

    logdata["info"] = d

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

    with open("results/output.log.json", "r") as logfile:
        data = json.loads(logfile.read())
        # print(data)
        
        url = 'http://app.dockysec.xyz:5000/host-results'
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")

def container_scan(scanid):
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Starting Container Scan{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# Checks for container security.{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    
    rc = call("./container.sh", shell=True)

    nm = nmap.PortScanner()
    nm.scan('127.0.0.1')

    results = []

    for port in nm['127.0.0.1']['tcp'].items():
        result = {
            "port" : port[0],
            "details": port[1],
        }

        results.append(result)
    
    # print(results)
    print(f"{Fore.YELLOW}[DEBUG] Found {len(results)} open ports{Style.RESET_ALL}")

    logdata = {}

    with open("results/output.log.json","r") as logfile:
        logdata = json.load(logfile)

    logdata["containerscan"] = results

    with open("results/output.log.json","w") as logfile:
        print(f"{Fore.YELLOW}[DEBUG] Writing result to the log file at results/output.log.json{Style.RESET_ALL}")
        json.dump(logdata, logfile, ensure_ascii=False, indent=4)

    with open("results/output.log.json", "r") as logfile:
        data = json.loads(logfile.read())
        # print(data)

        url = 'http://app.dockysec.xyz:5000/container-results?id=' + scanid
        print(f"{Fore.YELLOW}[DEBUG] Sending results to the server {url}{Style.RESET_ALL}")

        r = requests.post(url, json=data)

        if(r.status_code == 200):
            print(f"{Fore.YELLOW}[DEBUG] Successfully sent{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[DEBUG] Something went wrong, please try again{Style.RESET_ALL}")    

@click.command()							
@click.argument('mode', type=str)
@click.option('--scantype', type=str, help='Please mention scan type (host/container)')
@click.option('--scanid', type=str, help='Please mention scan id')
@click.option('--dockerfile', type=str, default="./samples/Dockerfile", help='Dockerfile location')
@click.option('--composefile', type=str, default="./samples/docker-compose3.yml", help='Docker-compose location')

def main(mode,scantype, dockerfile,composefile,scanid):
    print(f"{Fore.GREEN}\n# DockySec v1.0 \n{Style.RESET_ALL}")

    if which("nmap") is None:
        print(f"{Fore.RED}[IMPORTANT] Nmap is not installed{Style.RESET_ALL}")
        exit()
        # print(f"{Fore.YELLOW}[DEBUG] Installing nmap \n{Style.RESET_ALL}")
        # call('sudo apt install --no-install-recommends -y nmap', shell=True, stdout=DEVNULL, stderr=DEVNULL)


    #set permissions on results folder
    subprocess.call(['chmod', '+xrw', 'results/'])

    if mode == 'scan':
        if scantype == "host":
            sid = uuid.uuid4()

            print(f"{Fore.RED}[IMPORTANT] Please remember this scan id to run container specific scans {sid}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans \n{Style.RESET_ALL}")

            if os.path.exists("./results/output.log.json"):
                os.remove("results/output.log.json")
            if os.path.exists("results/output.log"):
                os.remove("results/output.log")

            cis_check()
            host_scan()
            scanDockerFile(dockerfile)
            scanComposeFile(composefile)
            finish(sid)
            
        # if scantype == "container":
        #     if not scanid:
        #         print(f"{Fore.RED}[ERROR] Please define scanId{Style.RESET_ALL}")
        #         exit() 
        #     else:    
        #         print(f"{Fore.YELLOW}[DEBUG] Cleaning previous scans {Style.RESET_ALL}")
        #         print(f"{Fore.YELLOW}[DEBUG] Using Scan ID {scanid} {Style.RESET_ALL}")

        #         if os.path.exists("./results/output.log.json"):
        #             os.remove("results/output.log.json")
        #         if os.path.exists("results/output.log"):
        #             os.remove("results/output.log")

        #         container_scan(scanid)

        if not scantype:
            print(f"{Fore.RED}[ERROR] Please define scantype{Style.RESET_ALL}")

    if mode == 'fix':
        print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
        print(f"{Fore.GREEN}# Starting Docky-Sec Fixer Module{Style.RESET_ALL}")
        print(f"{Fore.GREEN}# This will fix your vulnerable DockerFiles and ComposeFiles{Style.RESET_ALL}")
        print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")

        rc = call("./app/fixer.sh", shell=True)


if __name__ == '__main__':
    main()

# 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
# git remote set-url origin https://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@github.com/hackerzeus12/docky-sec.git
# git pw : 0fTgtc7gvLPU8tI
# hackerzeus12@gmail.com

# new - c
# sitharu@dockysec.lk

# pm2 serve build 3000 --name client --spa
# pm2 delete server
# pm2 start index.js --name server

# git clone https://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@github.com/hackerzeus12/docky-sec.git

# docker stop $(docker ps -a -q)

# steps
# chmod +x init.sh
# ./init.sh

# python3 main.py scan --scantype=host --dockerfile=../dockers/CVE-2017-14849-Nodejs/Dockerfile --composefile=../dockers/CVE-2017-1000353-Jenkins/docker-compose.yml
# python3 main.py scan --scantype=host --dockerfile=/home/dushyantha_world/dockers/CVE-2017-14849-Nodejs/Dockerfile --composefile=/home/dushyantha_world/dockers/CVE-2017-1000353-Jenkins/docker-compose.yml
# python3 main.py fix

# sudo docker-compose up -d
#  sudo docker exec -it cve-2017-14849-nodejs_node_1 bash

# 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
# git clone https://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@github.com/hackerzeus12/dockysec-client.git
# git clone https://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@github.com/hackerzeus12/dockysec-server.git
