Python based tool that allows for scanning/discovering all subdomains of a given domain.
i) Scan all open ports of a host address.
ii) Check if it has XSS header enabled or not
iii) Checks if the domain has a valid SSL certificate

All the files are uploaded and the neccessary libraries can be installed by running 
```text
pip install -r requirements.txt
```
To execute the script run
```text
python script.py
```

The project has 2 lists of subdomains ,one is a shorter list and another is a list containing around 9.5K subdomains.
The script asks the user for a choice the longer list would take a bigger amount of time to produce results.

After the script is successfully completed the results can be found in the logs.txt file.

