import requests
import concurrent
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from socket import AF_INET
from socket import SOCK_STREAM
from socket import socket
from socket import gethostbyname
import nmap
import os
import subprocess
global subdomain


#taking domain name as input
domain = input("Enter Domain: ")
cmd = f'curl -sI {domain}'
output = subprocess.getoutput(cmd)

chk = 'X-XSS-Protection: 0'

#ask the user fro choice of searchng all or a subset that is much more common subdomains
print("Want to Search:\n 1:Common Subdomains \n 2:All Subdomains ")
choice = int(input())
if choice == 1:
	with open('common_subdomains','r') as file:
		name = file.read()
		subdomain = name.splitlines()
else:
	with open('all_subdomains','r') as file:
		name = file.read()
		subdomain = name.splitlines()


#using multithreading to scan the domains in a short amount of time as linear scanning takes a lot of time
valid_subdomains = list()
threads = 30
urls = [f"https://{item}.{domain}" for item in subdomain]
def check(url):
	try:
		r= requests.get(url,verify=True)
		full_response = (r.status_code,url)
		valid_subdomains.append(full_response)
		sleep(1)
		return r.json
	except requests.ConnectionError:
		pass
with ThreadPoolExecutor(max_workers=threads) as executor:
    future_to_url = {executor.submit(check,url) for url in urls}
    for future in concurrent.futures.as_completed(future_to_url):
	    try:
	        data = future.result()
	    except Exception as e:
	        print('Looks like something went wrong:', e)
# print(valid_subdomains)	  

#check for ssl certification of the website  
ssl_enable = True
try:
	response1 = requests.get(f'https://www.{domain}', verify=True)
except:
	ssl_enable = False	

# subdomains are now stored in valid_subdomains list and can be printed for further use
ssl_cert = ""
if ssl_enable:
	ssl_cert = "Enabled"
else:
	ssl_cert = "Disabled"
try:
	file_handler = open('logs.txt','x')
except:
	pass

#we create a logs.txt file if it doesn't exist and store all the result in that file
file_handler = open('logs.txt','w')
file_handler.write(f"URL : {domain}\n")
file_handler.write("..............................................................................\n")
file_handler.write("Subdomains :\n")

for item in valid_subdomains:
	file_handler.write(f"- {item[0]} {item[1]}\n")

file_handler.write(f" Total subdomain are: {len(valid_subdomains)}\n")
file_handler.write("..............................................................................\n")

#writing to log about SSL details of domain
file_handler.write(f"SSL Details: \n -SSL : {ssl_cert}\n - issued to : {domain}\n")
file_handler.write(".............................................................................\n")
file_handler.write(f"Ports: \n")

domains = gethostbyname(domain)
# print(domains)

scanner = nmap.PortScanner()

def test_port_number(host, port):
    # create and configure the socket
    with socket(AF_INET, SOCK_STREAM) as sock:
        # set a timeout of a few seconds
        sock.settimeout(2)
        # connecting may fail
        try:
            # attempt to connect
            sock.connect((host, port))
            # a successful connection was made
            return True
        except:
            # ignore the failure
            return False

PORTS = range(250)
with ThreadPoolExecutor(max_workers = threads) as executor:
        # dispatch all tasks
        results = executor.map(test_port_number, [domain]*len(PORTS), PORTS)
        # report results in order
        for port,is_open in zip(PORTS,results):
            if is_open:
            	file_handler.write(f"Port {port} : Open\n")

file_handler.write("..............................................................................\n")

file_handler.write(f"Header : \n")
cross_site = ""
if chk in output:
	cross_site = "Enabled"
else:
	cross_site = 'Not Enabled'

file_handler.write(f"X-XSS-Protection : {cross_site}\n")
