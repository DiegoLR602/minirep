# This an interactive script that gathers information about an IP address from various services

from shodan import Shodan
import argparse
import colorama
import json
import os
import requests
from os.path import dirname
from termcolor import colored,cprint

def fetch_vt_reputation(address,config):

    headers = {'x-apikey': config['vt_api_key']}
    response = requests.get(url=f"{config['vt_api_url']}/ip_addresses/{address}", headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed VT IP address lookup for {address}. Status code: {response.status_code}. Message: {response.text}")
        return

def shodan_scan(config, address):
    result = config.host(address)
    open_ports = result['ports']
    tags = result['tags']
    isp = result['isp']
    org = result['org']
    data = result['data'][0]
    try:
        product = data['product']
    except KeyError:
        product = "N/A"
    try:
        os = data['os']
    except KeyError:
        os = "N/A"
    try:
        location = data['location']
    except KeyError:
        location = "N/A"
    try:
        vulns = list(data['vulns'].keys())
    except KeyError:
        vulns = "N/A"

    cprint(colored("""
-------------
SHODAN DATA
-------------""","blue"))
    print("Open ports: ", open_ports)
    print("Tags: ", tags)
    print("ISP: ", isp)
    print("Organization: ", org)
    # print("Data: ", data)
    print("Product Version: ", product)
    print("Operating System: ", os)
    print("IP Location: ", location)
    print("Possible Vulnerabilities: ")
    if vulns == "N/A":
        print ("N/A")
    else:
        for vuln in vulns:
            print("-", vuln)

def main(args):

    colorama.init()

    # If no address was supplied, prompt
    if not args.Address:
        ip_addr = input("Enter the IP address you would like to check: ")
    else:
        ip_addr = args.Address

    # Load config. Print warning and exit if not found
    try:
        config_file_path = os.path.join(dirname(os.path.realpath(__file__)),"minirep.json")
        config = json.load(open(config_file_path))
    except Exception as e:
        print(f"Failed to load config file from {config_file_path}.\r\nException: {e}")
        return

    # Print the directions. Comment this out when you no longer need it
    # render_directions()

    # Query VirusTotal for IP reputation. Feel free to discard this section or use it in a different way
    shodan_api = Shodan(config['sh_api_key'])
    shodan_scan(shodan_api, ip_addr)
    if vt_rep := fetch_vt_reputation(ip_addr,config):
        cprint(colored("""
----------------------------
VIRUS TOTAL REPUTATION DATA
----------------------------""",'green'))
        print(f"Reputation Score: {vt_rep['data']['attributes']['reputation']}")
        print(f"Harmless Votes: {vt_rep['data']['attributes']['total_votes']['harmless']}")
        print(f"Malicious Votes: {vt_rep['data']['attributes']['total_votes']['malicious']}")
    
    while True:
        decision = input("Based on these results, would you like to DROP, ALERT, or PASS connections to this device? ")
        if (decision.upper() == "DROP"):
            print("Connection successfully dropped.")
            break
        elif (decision.upper() == "ALERT"):
            print("Alert successfully issued.")
            break
        elif (decision.upper() == "PASS"):
            print("Connection successfully passed.")
            break
        else:
            print("Invalid input. Please only type DROP, ALERT, or PASS to make your decision.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--Address", help ="IP address to scan")
    
    args = parser.parse_args()
    main(args)