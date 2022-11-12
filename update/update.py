import pymongo
import json 
import requests
from colorama import Fore, Style
import wget
from wget import bar_thermometer,bar_adaptive 
import os
import requests
import time
import click
import json
import uuid
from json.decoder import JSONDecodeError
from nested_lookup import nested_lookup
from datetime import date
import zipfile
import shutil

# @click.command()

def process(files):

    # filelist = ["./nvdcve-1.1-2017.json","./nvdcve-1.1-2018.json","./nvdcve-1.1-2019.json","./nvdcve-1.1-2020.json","./nvdcve-1.1-2021.json","./nvdcve-1.1-2022.json"]
    for file in files:
        """Open for read"""
        filepath = "/home/dushyantha_world/docky-sec/update/latest/" + file
        f = open(filepath)
        data = json.load(f)

        vulns = []

        for item in data['CVE_Items']:
            cve_id = item["cve"]["CVE_data_meta"]["ID"]
            created_at = item["publishedDate"]
            updated_at = item["lastModifiedDate"]
            references = item["cve"]["references"]["reference_data"]
            summary = item["cve"]["description"]["description_data"][0]["value"]
            cvss2 = (
                item["impact"]["baseMetricV2"]
                if "baseMetricV2" in item["impact"]
                else None
            )
            cvss3 = (
                item["impact"]["baseMetricV3"]
                if "baseMetricV3" in item["impact"]
                else None
            )

            if cvss2 is None or cvss3 is None:
                continue

            # Construct CWE and CPE lists
            cwes = get_cwes(
                item["cve"]["problemtype"]["problemtype_data"][0]["description"]
            )

            cpes = convert_cpes(item["configurations"])

            # start formula
            if cvss3 is not None:
                if "exploitabilityScore" in cvss3:
                    ex = (cvss3["exploitabilityScore"])
                if "impactScore" in cvss3:
                    im = (cvss3["impactScore"])
            if cvss2 is not None:
                if "exploitabilityScore" in cvss2:
                    ex = (cvss2["exploitabilityScore"])
                if "impactScore" in cvss2:
                    im = (cvss2["impactScore"])

            score = (2 * ex * im)/(ex + im)

            published_year = created_at.split("T")[0].split("-")[0]
            current_year = date.today().year

            if int(published_year) >= int(current_year) - 5:
                pass
            else:
                if int(published_year) >= int(current_year) - 10: 
                    score = score * 0.5 
                else:
                    score = score * 0.25

            if cvss3 is not None and "cvssV3" in cvss3 and "privilegesRequired" in cvss3["cvssV3"]:  
                if cvss3["cvssV3"]["privilegesRequired"] is not None and cvss3["cvssV3"]["privilegesRequired"] == "HIGH":
                    score = score * 0.80 
                elif cvss3["cvssV3"]["privilegesRequired"] is not None and cvss3["cvssV3"]["privilegesRequired"] == "LOW":
                    score = score * 0.95 

            if cvss2 is not None and "cvssV2" in cvss2 and "attackComplexity" in cvss2["cvssV2"]:
                if cvss2["cvssV2"]["attackComplexity"] is not None and  cvss2["cvssV2"]["attackComplexity"] == "HIGH":
                    score = score * 0.80 
                elif cvss2["cvssV2"]["attackComplexity"] is not None and cvss2["cvssV2"]["attackComplexity"] == "MEDIUM":
                    score = score * 0.95 

            if round(score, 2) >= 7:
                vulns.append({
                "cve_id":cve_id,
                "created_at":created_at,
                "updated_at":updated_at,
                "references":references,
                "summary":summary,
                "cvss2":cvss2,
                "cvss3":cvss3,
                "cwes":cwes,
                "cpes":cpes,
                "score":round(score, 2)
            })
          
        
        # Closing file
        f.close()

        # print(vulns[0])
        # print(json.dumps(vulns[0], indent=4, sort_keys=True))

        with open(file, 'w', encoding='utf-8') as f:
            json.dump(vulns, f, ensure_ascii=False, indent=4)

def get_uuid():
    return str(uuid.uuid4())    

def get_cwes(problems):
    """
    Takes a list of problems and return the CWEs ID.
    """
    return list(set([p["value"] for p in problems]))

def convert_cpes(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf
    # print(uris)
    affected = []

    for uri in uris:
        # print(uri.split(":")[3:6])
        affectedVendors = uri.split(":")[3]
        # print(affectedVendors)
        affectedProducts = uri.split(":")[4]
        # print(affectedProducts)
        affectedProductVersion = uri.split(":")[5]
        # print(affectedProductVersion)

        affected.append({
            "vendor": affectedVendors,
            "product": affectedProducts,
            "version": affectedProductVersion,
        })

    return affected

def main():
    print(f"{Fore.GREEN}\n# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# DockySec Vulenerability Management Platform{Style.RESET_ALL}")
    print(f"{Fore.GREEN}# --------------------------------------------------------------------------------------------{Style.RESET_ALL}")


    # get latest meta data
    x = requests.get('https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta')
    print(f"{Fore.YELLOW}[DEBUG] Getting metadata from NVD{Style.RESET_ALL}")

    # save metadata file retieved from nvd 
    meta = {}

    for line in x.text.splitlines():
        key = line.split(":")[0]
        value = line.split(":")[1]
        # print(key,value)

        meta[key] = value

    print(json.dumps(meta))

    # check with local file
    with open("/home/dushyantha_world/docky-sec/update/metadata.json","r") as inp:
        data = json.load(inp)

        localHash = data["sha256"]
        remoteHash = meta["sha256"]

        if not meta["sha256"] != data["sha256"]:
            print(f"{Fore.YELLOW}[DEBUG] Local Hash : {localHash} {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Latest Hash : {remoteHash} {Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[DEBUG] Hmm :( No new vulnerabilities {Style.RESET_ALL}")

        else:
            print(f"{Fore.YELLOW}[DEBUG] Wow :) We got new vulnerabilities {Style.RESET_ALL}")
            with open("/home/dushyantha_world/docky-sec/update/metadata.json","w+") as out:
                out.write(json.dumps(meta))
                print(f"{Fore.YELLOW}\n[DEBUG] Updating metadata file with latest data {Style.RESET_ALL}")


            print(f"{Fore.YELLOW}[DEBUG] Downloading latest vulnerabilties {Style.RESET_ALL}")

            if os.path.exists("latest.json.zip"):
                os.remove("latest.json.zip")
            if os.path.exists("modified.json"):
                os.remove("modified.json")

            print(f"{Fore.YELLOW}[DEBUG] Removing old files {Style.RESET_ALL}")
            # get latest meta data
            url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.zip"
            wget.download(url,bar=bar_adaptive,out="latest.json.zip" )
            print(f"{Fore.YELLOW}\n[DEBUG] File downloaded successfully {Style.RESET_ALL}")

            shutil.rmtree('latest')	
            print(f"{Fore.YELLOW}[DEBUG] Removing previous files {Style.RESET_ALL}")

            with zipfile.ZipFile("/home/dushyantha_world/docky-sec/update/latest.json.zip", 'r') as zip_ref:
                zip_ref.extractall("latest")

            os.rename("/home/dushyantha_world/docky-sec/update/latest/nvdcve-1.1-modified.json","/home/dushyantha_world/docky-sec/update/latest/modified.json")
            filelist = os.listdir('latest')

            print(f"{Fore.YELLOW}[DEBUG] Processing latest data ... Please wait{Style.RESET_ALL}")
            process(filelist)
            print(f"{Fore.YELLOW}[DEBUG] Processing completed{Style.RESET_ALL}")

            print(f"{Fore.YELLOW}[DEBUG] Connecting to Dockysec database {Style.RESET_ALL}")
            myclient = pymongo.MongoClient("mongodb+srv://zeus:eKWBkPbIJtbWGbZ8@cluster0.kelnyif.mongodb.net/UserData?retryWrites=true&w=majority")

            db = myclient["test"]
            collection  = db["vulneralabilities"]

            f = open("/home/dushyantha_world/docky-sec/update/modified.json")
            data = json.load(f)

            for item in data:
                j = {
                    "cve_id":item["cve_id"],
                    "cve_id":item["cve_id"],
                    "created_at":item["created_at"],
                    "updated_at":item["updated_at"],
                    "references":item["references"],
                    "summary":item["summary"],
                    "cvss2":item["cvss2"],
                    "cvss3":item["cvss3"],
                    "cwes":item["cwes"],
                    "cpes":item["cpes"],
                    "score":item["score"]
                }
                
                cveId = item["cve_id"]

                collection.update_one({"cve_id":item["cve_id"]}, {"$set" : j}, upsert = True )
                print(f"{Fore.YELLOW}[DEBUG] Updated : {cveId}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
