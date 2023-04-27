# minirep
This repository is used for the ISP-452 Threat Intelligence Lab. 

We will also use this project during our network analysis module to automate blocking of suspicious or malicious IP addresses.

API Used: Shodan API, VirusTotal API

# Prerequisites
1. Python 3.8+
2. VirusTotal API Key
3. Create a fork of the minirep repository

# Installation (Windows)
1. Launch PowerShell
2. Clone the repository: `git clone <URL of your forked repository>`
3. Change directories into the repository folder: `cd minirep`
4. Create the virtual environment: `python -m venv .`
5. Activate the virtual environment: `.\Scripts\activate`
6. Install the required packages: `pip3 install -r requirements.txt`
7. Create the config file (update the command with your API key from VT): 
```PowerShell
@{"vt_api_key"="YOUR_API_KEY_HERE";"vt_api_url"="https://www.virustotal.com/api/v3"} | ConvertTo-Json | Out-File .\minirep.json`
```
8. Run minirep.py: `python3 minirep.py`

# Installation (Linux)
1. Install python3-virtualenv (this is dependent on the OS you are running): `sudo apt install python3.10-venv`
2. Clone the repository: `git clone <URL of your forked repository>`
3. Change directories into the repository folder: `cd minirep`
4. Create the virtual environment: `python -m venv .`
5. Activate the virtual environment: `source ./bin/activate`
6. Install the required packages: `pip3 install -r requirements.txt`
7. Create the minirep.json config file: `vi minirep.json`
```json
{
    "vt_api_url":  "https://www.virustotal.com/api/v3",
    "vt_api_key":  "YOUR_API_KEY_HERE"
    "sh_api_key":  "YOUR_API_KEY_HERE"
}
```
8. Run minirep.py: `python3 minirep.py`

# Analysis
Based on the data you gather, render a verdict of either `DENY`, `ALERT`, `PASS`. 
* Denied IPs should be blocked from ingress/egress on your network. 
* Alerting IPs should be monitored for further activity. These will be subject to further inspection for a definitive verdict
* Passed IPs will be ignored

# Outcomes
- Interact with API services
- Understand IP reputation services and how they can assist with making decisions to protect your network
- Understand the limitations of these services (e.g. true & false positives, transience of IPs, etc.)
