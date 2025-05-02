#/bin/python3

from urllib.parse import urlparse
import subprocess
import argparse
import threading
import time
import requests
import urllib3
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

start=time.time()
parser=argparse.ArgumentParser("SubShadow")

# parser.add_argument('-d','--domain',dest="domain",help="Target Name")
parser.add_argument('-l','--filelist',dest="filelist",help="Trget domain file list")
argdata=parser.parse_args()


target = argdata.filelist

# class Domain:
#     virtotel="b396467c82cca7e9bb16d6812303efdb76514cd99eb7ef595a566ba429eedd6c"

#     print("\n[+] Start Gathering Subdomain\n")
        
#     with open(target, "r") as domains:
#         for domain in domains:
#             domain = domain.strip()
#             cmd = f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?domain={domain}&apikey={virtotel}' | jq -r '.subdomains[]' >> Output/subdomain.txt"
#             subprocess.run(cmd, shell=True)


#     def assetfinder():

#         file=open(f"{target}","r")
#         for f in file:
#             # print(f)
#             assetfinder=f"Tools/assetfinder {f} >> Output/subdomain.txt"
#             subprocess.run(assetfinder,shell=True)

#     def subfinder():
#         file=open(f"{target}","r")
#         for f in file:
#             subfinder=f"Tools/subfinder --silent -d {f.strip()} >> Output/subdomain.txt"
#             subprocess.run(subfinder,shell=True)

#     def Crt():
#         file=open(f"{target}","r")
#         for f in file:
#             url = f"https://crt.sh/?q={f}&output=json"
#             response = requests.get(url)

#             if response.status_code == 200:
#                 data = response.json()
#                 domains = set()
                
#                 for entry in data:
#                     for key in ['common_name', 'name_value']:
#                         if key in entry:
#                             values = entry[key].split('\n')
#                             for val in values:
#                                 # Remove wildcard and emails
#                                 val = val.replace('*.', '')
#                                 if not re.match(r"[^@]+@[^@]+\.[^@]+", val):
#                                     if re.match(r"^[^@\s]+\.[^\s]+$", val):
#                                         domains.add(val.strip())
                
#                 with open("Output/crt.txt", "w") as f:
#                     for domain in sorted(domains):
#                         f.write(domain + "\n")
#             else:
#                 print(f"Failed to fetch data, status code: {response.status_code}")

#     if __name__=="__main__":

#         process1=threading.Thread(target=assetfinder)
#         process2=threading.Thread(target=subfinder)
#         process3=threading.Thread(target=Crt)

#         process1.start()
#         process2.start()
#         process3.start()
#         process1.join()
#         process2.join() 
#         process3.join() 

#         subprocess.run("cat Output/crt.txt >> Output/subdomain.txt",shell=True)

#         subprocess.run("cat Output/subdomain.txt | uniq | sort > Output/subdomains.txt ",shell=True)

#         os.remove("Output/subdomain.txt")
#         os.remove("Output/crt.txt")
        


class HostEnum:
    def Validdomain(self):
        subprocess.run("grep -E '^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' Output/subdomains.txt > Output/temp_subdomains.txt",shell=True)
        os.remove("Output/subdomains.txt")

        file=open(f"{target}","r")
        for domain in file:
            domain = domain.strip()
            if domain:
                subprocess.run(f"grep '{domain}' Output/temp_subdomains.txt >> Output/subdomains.txt", shell=True)

        os.remove("Output/temp_subdomains.txt")
        print("\n")
        subprocess.run("cat Output/subdomains.txt | uniq | sort >  Output/uniq.txt",shell=True)
        subprocess.run("echo 'The Total Subdomains' && cat Output/uniq.txt | wc -l ",shell=True)
        os.remove("Output/subdomains.txt")
        subprocess.run("cat Output/uniq.txt > Output/subdomains.txt",shell=True)
        os.remove("Output/uniq.txt")
    
    @staticmethod
    def LiveHost():
        print("\n\n[+] Checking Live Host...\n")
        subprocess.run("cat Output/subdomains.txt | Tools/httpx -silent  >> Output/LiveDomains.txt",shell=True)
    
    @staticmethod
    def TargetEnum():
        subprocess.run("Tools/httpx -l Output/subdomains.txt -mc 404,000 -o Output/4XX.txt", shell=True)
        print("\n\n[+] Cname Checking...\n")

        with open("Output/4XX.txt", "r") as Url4xx:
            for inUrl in Url4xx:
                inUrl = inUrl.strip()
                hostname = urlparse(inUrl).hostname or inUrl  

                try:
                    cname = dns.resolver.resolve(hostname, "CNAME")
                    for val in cname:
                        result = f'[{val}] : {hostname}'
                        with open("Output/cname.txt", "a") as CnameFile:
                            CnameFile.write(f"{result}\n")
                            print(result)

                except dns.resolver.NoAnswer:
                    print(f"No CNAME record - {hostname}")
                except Exception as e:
                    print(f"Error with {hostname}: {e}")

        

HostEnum = HostEnum()
# HostEnum.Validdomain()
# HostEnum.LiveHost()
HostEnum.TargetEnum()

end=time.time()
print("\nTotal Time",end-start)
