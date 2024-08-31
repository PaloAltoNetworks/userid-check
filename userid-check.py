#!/usr/bin/env python3
# *****************************************************************************
# * Copyright (c) 2008-2024, Palo Alto Networks. All rights reserved.         *
# *                                                                           *
# * This Software is the property of Palo Alto Networks. The Software and all *
# * accompanying documentation are copyrighted.                               *
# *****************************************************************************
from getpass import getpass
import sys
import os
import csv
import logging
import xmltodict
from rich.console import Console
from rich.table import Table
from multiprocessing import Process
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing import cpu_count
import requests
import webbrowser
import argparse
import ipaddress
from argparse import RawTextHelpFormatter
requests.packages.urllib3.disable_warnings()
from OpenSSL import SSL
import socket
import datetime
# from termcolor import colored
# import pyfiglet
# # fonts = pyfiglet.FigletFont.getFonts()
# print((colored(pyfiglet.figlet_format("Certificate Expiry Tool", font='larry3d', width = 100, justify = 'center'), color = 'red')))

e = ""

parser = argparse.ArgumentParser(add_help=True,
                    formatter_class=RawTextHelpFormatter,
                    description='Usage Examples: \n\n\tpython3 redist-check.py -x\n\n\tpython3 redist-check.py -xw\n\n\tpython3 redist-check.py -xow\n\n\tpython3 redist-check.py -cxow\n\n\tpython3 redist-check.py -xw yourfile.html\n\n\tpython3 redist-check.py -xow yourfile.html\n\n\tpython3 redist-check.py -pcxow yourfile.html')

parser.add_argument("-x", action = "store_true", help="Optional - Disable Links Pop-Up")

parser.add_argument("-w", required='-o' in sys.argv, nargs='?', const='output.html', help="Optional - Create WebPage from output.  If no file is specified after '-w', then 'output.html' will be used")

parser.add_argument("-o", action = "store_true", help="Requires '-w' - Open Results in Web Browser")

parser.add_argument("-c", action = "store_true", help="Writes CSV (2 total)")

args = parser.parse_args()

if args.x:
    pass
else:
    webbrowser.open('https://live.paloaltonetworks.com/t5/customer-advisories/update-to-additional-pan-os-certificate-expirations-and-new/ta-p/572158', new = 2)

if args.w:
    html_file = args.w
    console = Console(record=True)
else:
    console = Console()

supported_panos_versions = ["8.1.21-h3", "8.1.25-h3", "8.1.26", "8.1.26-h1", "9.0.16-h7", "9.0.17-h5", "9.1.11-h5", "9.1.12-h7", "9.1.13-h5", "9.1.14-h8", "9.1.16-h5", "9.1.17", "9.1.19", "10.0.12-h5", "10.0.12-h6", "10.0.8-h11", "10.1.10-h5", "10.1.11-h5", "10.1.12", "10.1.3-h3", "10.1.4-h6", "10.1.5-h4", "10.1.6-h8", "10.1.7-h1", "10.1.8-h7", "10.1.9-h8", "10.1.12", "10.1.13", "10.1.14", "10.1.14-h2", "10.2.0-h2", "10.2.1-h1", "10.2.2-h4", "10.2.3-h12", "10.2.4-h10", "10.2.6-h1", "10.2.7-h3", "10.2.7-h6", "10.2.8", "10.2.8-h3", "10.2.8-h4", "10.2.8-h10", "10.2.8", "10.2.9", "10.2.9-h9", "10.2.10", "10.2.10-h2", "10.2.10-h3", "10.2.11", "11.0.0-h2", "11.0.1-h3", "11.0.2-h3", "11.0.3-h3", "11.0.3-h5", "11.0.3-h10", "11.0.3-h12", "11.0.4", "11.1.0-h2", "11.1.1", "11.1.2", "11.1.2-h1", "11.1.2-h4", "11.1.2-h9", "11.1.3", "11.1.3-h1", "11.1.3-h2", "11.1.3-h4", "11.1.4", "11.1.4-h1", "11.2.0", "11.2.1", "11.2.2-h1"]

unsupported_panos_versions = ["8.1.0", "8.1.1", "8.1.10", "8.1.11", "8.1.12", "8.1.12-h3", "8.1.13", "8.1.14", "8.1.14-h2", "8.1.15", "8.1.15-h3", "8.1.16", "8.1.17", "8.1.18", "8.1.19", "8.1.2", "8.1.20", "8.1.20-h1", "8.1.21", "8.1.21-h1", "8.1.22", "8.1.23", "8.1.23-h1", "8.1.24", "8.1.25-h1", "8.1.3", "8.1.4", "8.1.5", "8.1.6", "8.1.6-h2", "8.1.7", "8.1.8", "8.1.8-h5", "8.1.9", "8.1.9-h4", "9.0.0", "9.0.1", "9.0.10", "9.0.11", "9.0.12", "9.0.13", "9.0.14", "9.0.14-h3", "9.0.14-h4", "9.0.15", "9.0.16", "9.0.16-h2", "9.0.16-h3", "9.0.16-h5", "9.0.17-h4", "9.0.2", "9.0.2-h4", "9.0.3", "9.0.3-h2", "9.0.3-h3", "9.0.4", "9.0.5", "9.0.5-h3", "9.0.6", "9.0.7", "9.0.8", "9.0.9", "9.0.9-h1", "9.1.0", "9.1.1", "9.1.10", "9.1.11", "9.1.11-h2", "9.1.11-h3", "9.1.11-h4", "9.1.12", "9.1.12-h3", "9.1.12-h6", "9.1.13", "9.1.13-h1", "9.1.13-h3", "9.1.13-h4", "9.1.14", "9.1.14-h1", "9.1.14-h4", "9.1.14-h7", "9.1.15", "9.1.15-h1", "9.1.16", "9.1.16-h3", "9.1.2", "9.1.2-h1", "9.1.3", "9.1.3-h1", "9.1.4", "9.1.5", "9.1.6", "9.1.7", "9.1.8", "9.1.9", "10.0.0", "10.0.1", "10.0.10", "10.0.10-h1", "10.0.11", "10.0.11-h1", "10.0.11-h3", "10.0.12", "10.0.12-h3", "10.0.2", "10.0.3", "10.0.4", "10.0.5", "10.0.6", "10.0.7", "10.0.8", "10.0.8-h10", "10.0.8-h4", "10.0.8-h8", "10.0.9", "10.1.0", "10.1.1", "10.1.10", "10.1.10-h1", "10.1.10-h2", "10.1.11", "10.1.11-h1", "10.1.11-h4", "10.1.13", "10.1.14", "10.1.14-h2", "10.1.2", "10.1.3", "10.1.3-h2", "10.1.4", "10.1.4-h4", "10.1.5", "10.1.5-h1", "10.1.5-h2", "10.1.5-h3", "10.1.6", "10.1.6-h3", "10.1.6-h6", "10.1.6-h7", "10.1.7", "10.1.8", "10.1.8-h2", "10.1.8-h6", "10.1.9", "10.1.9-h1", "10.1.9-h3", "10.2.0", "10.2.0-h1", "10.2.1", "10.2.2", "10.2.2-h2", "10.2.3", "10.2.3-h11", "10.2.3-h2", "10.2.3-h4", "10.2.3-h9", "10.2.4", "10.2.4-h2", "10.2.4-h3", "10.2.4-h4", "10.2.5", "10.2.6", "10.2.7", "10.2.10-h4", "11.0.0", "11.0.0-h1", "11.0.1", "11.0.1-h2", "11.0.2-h1", "11.0.2-h2", "11.0.3", "11.0.3-h10", "11.0.3-h12", "11.0.4", "11.0.4-h5", "11.0.5", "11.0.5-h1", "11.1.0"]

supported_agent_versions = ["9.0.6", "9.0.6-101", "9.1.5", "9.1.5-108", "10.0.7", "10.0.7-104", "10.1.2", "10.1.2-104", "10.2.2", "10.2.2-111", "10.2.3-103", "11.0.1", "11.0.1-104"]

device_table = Table(title="Devices that require PANOS Upgrades and/or Agent Upgrades", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
device_table.add_column("Device Name", justify="center")
device_table.add_column("Serial Number", justify="center")
device_table.add_column("IP Address", width=18, justify="center")
device_table.add_column("Model", justify="center")
device_table.add_column("SW Version", justify="center")
device_table.add_column("Suggested PANOS Version", justify="center")
device_table.add_column("Agent IP", justify="center")
device_table.add_column("Agent Type", justify="center")
device_table.add_column("Agent Version", justify="center")
device_table.add_column("Suggested Agent Version", justify="center")

supported_panos_table = Table(title="PANOS Devices with Agents are on a Supported PANOS Version", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
supported_panos_table.add_column("Device Name", justify="center")
supported_panos_table.add_column("Serial Number", justify="center")
supported_panos_table.add_column("IP Address", width=18, justify="center")
supported_panos_table.add_column("Model", justify="center")
supported_panos_table.add_column("SW Version", justify="center")
supported_panos_table.add_column("Suggested PANOS Version", justify="center")
supported_panos_table.add_column("User-ID Agents Present?", justify="center")
supported_panos_table.add_column("TS Agents Present?", justify="center")

unsupported_panos_table = Table(title="PANOS Devices with Agents that require PANOS Upgrades", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
unsupported_panos_table.add_column("Device Name", justify="center")
unsupported_panos_table.add_column("Serial Number", justify="center")
unsupported_panos_table.add_column("IP Address", width=18, justify="center")
unsupported_panos_table.add_column("Model", justify="center")
unsupported_panos_table.add_column("SW Version", justify="center")
unsupported_panos_table.add_column("Suggested PANOS Version", justify="center")
unsupported_panos_table.add_column("User-ID Agents Present?", justify="center")
unsupported_panos_table.add_column("TS Agents Present?", justify="center")

ignore_panos_table = Table(title="PANOS Devices without Agents", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
ignore_panos_table.add_column("Device Name", justify="center")
ignore_panos_table.add_column("Serial Number", justify="center")
ignore_panos_table.add_column("IP Address", width=18, justify="center")
ignore_panos_table.add_column("Model", justify="center")
ignore_panos_table.add_column("SW Version", justify="center")
ignore_panos_table.add_column("Suggested PANOS Version", justify="center")
ignore_panos_table.add_column("User-ID Agents Present?", justify="center")
ignore_panos_table.add_column("TS Agents Present?", justify="center")

supported_agent_table = Table(title="Discovered Agents that are on a Supported Agent Version", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
supported_agent_table.add_column("Agent IP", justify="center")
supported_agent_table.add_column("Agent Type", justify="center")
supported_agent_table.add_column("Agent Version", justify="center")
supported_agent_table.add_column("Suggested Agent Version", justify="center")

unsupported_agent_table = Table(title="Discovered Agents that require Upgrades", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
unsupported_agent_table.add_column("Agent IP", justify="center")
unsupported_agent_table.add_column("Agent Type", justify="center")
unsupported_agent_table.add_column("Agent Version", justify="center")
unsupported_agent_table.add_column("Suggested Agent Version", justify="center")

reachable_count = 0
devices_no_agent = 0
agents_checked = 0
devices_failed = 0
agents_failed = 0
not_reachable = 0
agent_ip = []
agent_ip_failed = []
total_devices = []
panos_list = []
agent_list = []
panos_devices = 'panos-devices.csv'
panos_agents = 'panos-agents.csv'

def get_devices():
    try:
        if len(sys.argv) == 1:
            filename = input("Enter filename that contains the list of Panorama and PANOS Device IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            with open(filename) as df:
               devices = df.read().splitlines()

            devices = [x.replace(' ', '') for x in devices]

            while("" in devices):
                devices.remove("")

        else:
            filename = input("Enter filename that contains the list of Panorama and PANOS Device IP Addresses: ")
            username = input("Login: ")
            password = getpass()
            malformed_ipaddrs = []
            with open(filename) as df:
               devices = df.read().splitlines()

            devices = [x.replace(' ', '') for x in devices]

            while("" in devices):
                devices.remove("")

        return devices, username, password, filename

    except FileNotFoundError:
        print('File Not Found')
        k=input("press Enter to exit")
        raise SystemExit(1)

def process_list(ip):
    global reachable_count, agents_checked, devices_failed, agents_failed, agent_ip, agent_ip_failed, total_devices, panos_list, agent_list, not_reachable
    skip = False
    sys_info_response = ''
    api_response = ''
    api_key = ''
    userid_agents_present = ''
    ts_agents_present= ''
    try:
        ip = str(ipaddress.ip_address(ip))
        uri = "/api/?type=keygen&user=" + username + "&password=" + requests.utils.quote(password)
        full_url = "https://" + ip + uri
        api_response = requests.post(full_url, verify=False, timeout=15)
        result_dict = xmltodict.parse(api_response.text)
        if 'key' in result_dict['response']['result'].keys():
            api_key = result_dict['response']['result']['key']
            #logging.debug("API Key: " + api_key)
            uri1 = "/api/?type=op&cmd=<show><system><info></info></system></show>&key=" + api_key
            full_url = "https://" + ip + uri1
            sys_info_response = requests.post(full_url, verify=False)
            dev_name_version = xmltodict.parse(sys_info_response.text)
            model = dev_name_version['response']['result']['system']['model']
            devicename =  dev_name_version['response']['result']['system']['devicename']
            serial = dev_name_version['response']['result']['system']['serial']
            family = dev_name_version['response']['result']['system']['family']
            panos_version = dev_name_version['response']['result']['system']['sw-version']
            recommended_version = ""

            if dev_name_version['response']['result']['system']['sw-version'] in supported_panos_versions:
                supported_version = "Yes"
            else:
                supported_version = "No"

            if panos_version in unsupported_panos_versions:
                if panos_version  == "8.1.0" or panos_version == "8.1.1" or panos_version == "8.1.2" or panos_version == "8.1.3" or panos_version == "8.1.4" or panos_version == "8.1.5" or panos_version == "8.1.6" or panos_version == "8.1.6-h2" or panos_version == "8.1.7" or panos_version == "8.1.8" or panos_version == "8.1.8-h5" or panos_version == "8.1.9" or panos_version == "8.1.9-h4" or panos_version == "8.1.10" or panos_version == "8.1.11" or panos_version == "8.1.12" or panos_version == "8.1.12-h3" or panos_version == "8.1.13" or panos_version == "8.1.14" or panos_version == "8.1.14-h2" or panos_version == "8.1.15" or panos_version == "8.1.15-h3" or panos_version == "8.1.16" or panos_version == "8.1.17" or panos_version == "8.1.18" or panos_version == "8.1.19" or panos_version == "8.1.20" or panos_version == "8.1.20-h1" or panos_version == "8.1.21" or panos_version == "8.1.21-h1":
                	recommended_version = "8.1.21-h3"

                if panos_version == "8.1.22" or panos_version == "8.1.23" or panos_version == "8.1.23-h1" or panos_version == "8.1.24" or panos_version == "8.1.25-h1":
                	recommended_version = "8.1.25-h3"

                if panos_version  == "9.0.0" or panos_version == "9.0.1" or panos_version == "9.0.2" or panos_version == "9.0.2-h4" or panos_version == "9.0.3" or panos_version == "9.0.3-h2" or panos_version == "9.0.3-h3" or panos_version == "9.0.4" or panos_version == "9.0.5" or panos_version == "9.0.5-h3" or panos_version == "9.0.6" or panos_version == "9.0.7" or panos_version == "9.0.8" or panos_version == "9.0.9" or panos_version == "9.0.9-h1" or panos_version == "9.0.10" or panos_version == "9.0.11" or panos_version == "9.0.12" or panos_version == "9.0.13" or panos_version == "9.0.14" or panos_version == "9.0.14-h3" or panos_version == "9.0.14-h4" or panos_version == "9.0.15" or panos_version == "9.0.16" or panos_version == "9.0.16-h2" or panos_version == "9.0.16-h3" or panos_version == "9.0.16-h5":
                	recommended_version = "9.0.16-h7"

                if panos_version == "9.0.17-h4":
                	recommended_version = "9.0.17-h5"

                if panos_version  == "9.1.0" or panos_version == "9.1.1" or panos_version == "9.1.2" or panos_version == "9.1.2-h1" or panos_version == "9.1.3" or panos_version == "9.1.3-h1" or panos_version == "9.1.4" or panos_version == "9.1.5" or panos_version == "9.1.6" or panos_version == "9.1.7" or panos_version == "9.1.8" or panos_version == "9.1.9" or panos_version == "9.1.10" or panos_version == "9.1.11" or panos_version == "9.1.11-h2" or panos_version == "9.1.11-h3" or panos_version == "9.1.11-h4":
                	recommended_version = "9.1.11-h5"

                if panos_version == "9.1.12" or panos_version == "9.1.12-h3" or panos_version == "9.1.12-h6":
                	recommended_version = "9.1.12-h7"

                if panos_version == "9.1.13" or panos_version == "9.1.13-h1" or panos_version == "9.1.13-h3" or panos_version == "9.1.13-h4":
                	recommended_version = "9.1.13-h5"

                if panos_version == "9.1.14" or panos_version == "9.1.14-h1" or panos_version == "9.1.14-h4" or panos_version == "9.1.14-h7":
                	recommended_version = "9.1.14-h8"

                if panos_version == "9.1.15" or panos_version == "9.1.15-h1" or panos_version == "9.1.16" or panos_version == "9.1.16-h3":
                	recommended_version = "9.1.16-h5"

                if panos_version  == "10.0.0" or panos_version == "10.0.1" or panos_version == "10.0.2" or panos_version == "10.0.3" or panos_version == "10.0.4" or panos_version == "10.0.5" or panos_version == "10.0.6" or panos_version == "10.0.7" or panos_version == "10.0.8" or panos_version == "10.0.8-h10" or panos_version == "10.0.8-h4" or panos_version == "10.0.8-h8":
                	recommended_version = "10.0.8-h11"

                if panos_version  == panos_version == "10.0.9" or panos_version == "10.0.10" or panos_version == "10.0.10-h1" or panos_version == "10.0.11" or panos_version == "10.0.11-h1" or panos_version == "10.0.11-h3":
                	recommended_version = "10.0.11-h4"

                if panos_version  == "10.0.12" or panos_version == "10.0.12-h3":
                	recommended_version = "10.0.12-h5"

                if panos_version  == "10.1.0" or panos_version == "10.1.1" or panos_version == "10.1.2" or panos_version == "10.1.3" or panos_version == "10.1.3-h2":
                	recommended_version = "10.1.3-h3"

                if panos_version  == "10.1.4" or panos_version == "10.1.4-h4":
                	recommended_version = "10.1.4-h6"

                if panos_version  == panos_version == "10.1.5" or panos_version == "10.1.5-h1" or panos_version == "10.1.5-h2" or panos_version == "10.1.5-h3":
                	recommended_version = "10.1.5-h4"

                if panos_version  == "10.1.6" or panos_version == "10.1.6-h3" or panos_version == "10.1.6-h6" or panos_version == "10.1.6-h7":
                	recommended_version = "10.1.6-h8"

                if panos_version  == "10.1.7":
                	recommended_version = "10.1.7-h1"

                if panos_version  == "10.1.8" or panos_version == "10.1.8-h2" or panos_version == "10.1.8-h6":
                	recommended_version = "10.1.8-h7"

                if panos_version  == "10.1.9" or panos_version == "10.1.9-h1" or panos_version == "10.1.9-h3":
                	recommended_version = "10.1.9-h8"

                if panos_version  == "10.1.10" or panos_version == "10.1.10-h1" or panos_version == "10.1.10-h2":
                	recommended_version = "10.1.10-h5"

                if panos_version  == "10.1.11" or panos_version == "10.1.11-h1" or panos_version == "10.1.11-h4":
                	recommended_version = "10.1.11-h5"

                if panos_version  == "10.2.0" or panos_version == "10.2.0-h1":
                	recommended_version = "10.2.0-h2"

                if panos_version  == "10.2.1":
                	recommended_version = "10.2.1-h1"

                if panos_version  == "10.2.2" or panos_version == "10.2.2-h2":
                	recommended_version = "10.2.2-h4"

                if panos_version  == "10.2.3" or panos_version == "10.2.3-h2" or panos_version == "10.2.3-h4" or panos_version == "10.2.3-h9" or panos_version == "10.2.3-h11":
                	recommended_version = "10.2.3-h12"

                if panos_version  == "10.2.4" or panos_version == "10.2.4-h2" or panos_version == "10.2.4-h3" or panos_version == "10.2.4-h4":
                	recommended_version = "10.2.4-h10"

                if panos_version  == "10.2.5" or panos_version == "10.2.6":
                	recommended_version = "10.2.6-h1"

                if panos_version  == "10.2.7":
                	recommended_version = "10.2.7-h3"

                if panos_version  == "11.0.0" or panos_version == "11.0.0-h1":
                	recommended_version = "11.0.0-h2"

                if panos_version  == "11.0.1" or panos_version == "11.0.1-h2":
                	recommended_version = "11.0.1-h3"

                if panos_version  == "11.0.2-h1" or panos_version == "11.0.2-h2":
                	recommended_version = "11.0.2-h3"

                if panos_version  == "11.0.3":
                	recommended_version = "11.0.3-h3"

                if panos_version  == "11.1.0":
                	recommended_version = "11.1.0-h2"
            else:
                recommended_version = "Supported PANOS Version"

            uri6 = "/api/?type=op&cmd=<show><user><user-id-agent><config><all/></config></user-id-agent></user></show>&key=" + api_key
            full_url = "https://" + ip + uri6
            user_id_config_response = requests.post(full_url, verify=False)
            user_id_agents = xmltodict.parse(user_id_config_response.text)
            if 'result' in user_id_agents['response']:
                agent_info = user_id_agents['response']['result']
                if "Host: " in agent_info:
                    userid_agents_present = "Yes"
                    agent_type = 'User-ID'
                    userid_agent_ip = ''
                    agent_port = ''
                    agent_os = ''
                    agent_version = ''
                    agent_upgrade = ''
                    for line in agent_info.splitlines():
                        if "Host:" in line:
                            userid_agent_ip = line.split('Host: ')[1].split('(')[0]
                            agent_port = line.split('):')[1].split('\n')[0]
                            if ":" in userid_agent_ip:
                                userid_agent_ip = [userid_agent_ip[:userid_agent_ip.rindex(':')], userid_agent_ip[userid_agent_ip.rindex(':')+1:]][0]

                        if "OS: " in line:
                            agent_os = line.split('OS: ')[1].split('\n')[0]

                        if "Product Version: " in line:
                            agent_version = line.split('Product Version: ')[1].split('\n')[0]
                            try:
                                context = SSL.Context(SSL.SSLv23_METHOD)
                                conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                                conn.connect((userid_agent_ip, int(agent_port)))
                                conn.do_handshake()
                                cert = conn.get_peer_certificate()
                                conn.close()
                                date_format = '%Y-%m-%d %H:%M:%S'
                                expiration_date = datetime.datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
                                if datetime.datetime.strptime(str(expiration_date), date_format) <= datetime.datetime(2024, 11, 18, 18, 50, 33):
                                    check_version = float(".".join(agent_version.split(".")[:2]))
                                    if check_version == 9.0:
                                        agent_upgrade = "9.0.6-101"
                                    if check_version == 9.1:
                                        agent_upgrade = "9.1.5-108"
                                    if check_version == 10.0:
                                        agent_upgrade = "10.0.7-104"
                                    if check_version == 10.1:
                                        agent_upgrade = "10.1.2-104"
                                    if check_version == 10.2:
                                        agent_upgrade = "10.2.3-103"
                                    if check_version == 11.0:
                                        agent_upgrade = "11.0.1-104"

                                    device_table.add_row(devicename, serial, ip, model, panos_version, recommended_version, userid_agent_ip, agent_type, agent_version, agent_upgrade)
                                    agent_list.append([userid_agent_ip, agent_type, agent_version, agent_upgrade])
                                    agent_ip.append(userid_agent_ip)

                                else:
                                    agent_upgrade = "Supported Agent Version"
                                    device_table.add_row(devicename, serial, ip, model, panos_version, recommended_version, userid_agent_ip, agent_type, agent_version, agent_upgrade)
                                    agent_list.append([userid_agent_ip, agent_type, agent_version, agent_upgrade])
                                    agent_ip.append(userid_agent_ip)

                            except IOError:
                                agent_ip_failed.append(userid_agent_ip)
                                print("User-ID Agent with IP Address:", userid_agent_ip, "could not be contacted.")

                            except SSL.SysCallError:
                                agent_ip_failed.append(userid_agent_ip)
                                print("User-ID Agent with IP Address:", userid_agent_ip, "could not be contacted.")

                else:
                    userid_agents_present = "No"
                    pass

            else:
                userid_agents_present = "No"
                pass

            uri7 = "/api/?type=op&cmd=<show><user><ts-agent><state>all</state></ts-agent></user></show>&key=" + api_key
            full_url = "https://" + ip + uri7
            ts_config_response = requests.post(full_url, verify=False)
            ts_agents = xmltodict.parse(ts_config_response.text)
            if 'result' in ts_agents['response']:
                ts_agent_info = ts_agents['response']['result']
                if "Host: " in ts_agent_info:
                    ts_agents_present = "Yes"
                    agent_type = 'Terminal Server'
                    ts_agent_ip = ''
                    ts_agent_port = ''
                    ts_agent_upgrade = ''
                    for line in ts_agent_info.splitlines():
                        if "Host:" in line:
                            ts_agent_ip = line.split('Host: ')[1].split('(')[0]
                            ts_agent_port = [line[:line.rindex(':')], line[line.rindex(':')+1:]][1]
                            if ":" in ts_agent_ip:
                                ts_agent_ip = [ts_agent_ip[:ts_agent_ip.rindex(':')], ts_agent_ip[ts_agent_ip.rindex(':')+1:]][0]

                        if "Version" in line:
                            # ts_agent_version = [line[:line.rindex(':')], line[line.rindex(':')+2:]][1]
                            try:
                                context = SSL.Context(SSL.SSLv23_METHOD)
                                conn = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))
                                conn.connect((ts_agent_ip, int(ts_agent_port)))
                                conn.do_handshake()
                                cert = conn.get_peer_certificate()
                                conn.close()
                                date_format = '%Y-%m-%d %H:%M:%S'
                                expiration_date = datetime.datetime.strptime(cert.get_notAfter().decode("ascii"), "%Y%m%d%H%M%SZ")
                                if datetime.datetime.strptime(str(expiration_date), date_format) <= datetime.datetime(2024, 11, 18, 19, 20, 6):
                                    agent_upgrade = 'refer to advisory to get your recommended version'
                                    device_table.add_row(devicename, serial, ip, model, panos_version, recommended_version, ts_agent_ip, agent_type, 'N/A', agent_upgrade)
                                    agent_list.append([ts_agent_ip, agent_type, 'N/A', agent_upgrade])
                                    agent_ip.append(ts_agent_ip)

                                else:
                                    agent_upgrade = "Supported Agent Version"
                                    device_table.add_row(devicename, serial, ip, model, panos_version, recommended_version, ts_agent_ip, agent_type, 'N/A', agent_upgrade)
                                    agent_list.append([ts_agent_ip, agent_type, 'N/A', agent_upgrade])
                                    agent_ip.append(ts_agent_ip)

                            except IOError:
                                agent_ip_failed.append(ts_agent_ip)
                                print("Terminal Server Agent with IP Address:", ts_agent_ip, "could not be contacted.")

                            except SSL.SysCallError:
                                agent_ip_failed.append(ts_agent_ip)
                                print("Terminal Server Agent with IP Address:", ts_agent_ip, "could not be contacted.")
                else:
                    ts_agents_present = "No"
                    pass

            else:
                total_devices.append(ip)
                ts_agents_present = "No"
                pass

            print("Completed Checking Device", devicename, "with IP Address:", ip)
            panos_list.append([devicename, serial, ip, model, panos_version, recommended_version, userid_agents_present, ts_agents_present])
            total_devices.append(ip)

        else:
            print("Skipped", ip, "No API Key Returned.  Check Credentials/user privileges" )
            total_devices.append(ip)
            devices_failed+=1

    except IOError:
        logging.error("IP Address: "+ip+" connection was refused. Please check connectivity.")
        skip = True
        total_devices.append(ip)
        not_reachable+=1
        pass

    except KeyError:
        logging.error(ip+" Incorrect Username/Password, Command not supported on this platform or API Access is not allowed on this user account.")
        skip = True
        total_devices.append(ip)
        not_reachable+=1
        devices_failed+=1
        pass

    except AttributeError:
        logging.error("No API key was returned.  Insufficient privileges or incorrect credentials given.")
        skip = True
        total_devices.append(ip)
        devices_failed+=1
        pass

    except ValueError:
        print('Malformed IP Address or hostname -', ip, 'in filename called:', filename)
        skip = True
        total_devices.append(ip)
        devices_failed+=1
        pass

    except TypeError:
        print('Received invalid response. Agent not responding. Skipping IP', ip)
        skip = True
        userid_agents_present = 'No'
        ts_agents_present = 'No'
        panos_list.append([devicename, serial, ip, model, panos_version, recommended_version, userid_agents_present, ts_agents_present])
        total_devices.append(ip)
        pass

    except e:
        print(e)
        # print(ip, "Had an Issue.  Please Investigate.")
        skip = True
        total_devices.append(ip)
        devices_failed+=1
        pass

    if skip == True:
        skip = False
        total_devices.append(ip)
        pass

def multi_processing():
    pool = ThreadPool(processes=os.cpu_count())
    res = list(pool.apply_async(process_list, args=(ip,)) for ip in devices)
    pool.close()
    pool.join()
    results = [r.get() for r in res]

devices, username, password, filename = get_devices()
multi_processing()

print("\n\n")

panos_list.sort()
panos_list = [panos_list[i] for i in range(len(panos_list)) if i == 0 or panos_list[i] != panos_list[i-1]]
reachable_count = len(panos_list)

agent_list.sort()
agent_list = [agent_list[i] for i in range(len(agent_list)) if i == 0 or agent_list[i] != agent_list[i-1]]

if args.c:
    panos_fields = ['Device Name', 'Serial Number', 'IP Address', 'Model', 'SW Version', 'Suggested PANOS Version', 'User-ID Agents Present?', 'TS Agents Present?']
    agent_fields = ['Agent IP', 'Agent Type', 'Agent Version', 'Suggested Agent Version']

    with open(panos_devices, 'w') as s:
        write = csv.writer(s)
        write.writerow(panos_fields)
        write.writerows(panos_list)

        for x in panos_list:
            if x[5]  == 'Supported PANOS Version':
                supported_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])
            else:
                if x[6]  == 'No' and x[7] == 'No':
                    ignore_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])
                    devices_no_agent+=1
                else:
                    unsupported_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])

    with open(panos_agents, 'w') as s:
        write = csv.writer(s)
        write.writerow(agent_fields)
        write.writerows(agent_list)

        for x in agent_list:
            if x[3] == "Supported Agent Version":
                supported_agent_table.add_row(x[0], x[1], x[2], x[3])

            else:
                unsupported_agent_table.add_row(x[0], x[1], x[2], x[3])

else:
    for x in panos_list:
        if x[5]  == 'Supported PANOS Version':
            supported_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])
        else:
            if x[6]  == 'No' and x[7] == 'No':
                ignore_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])
                devices_no_agent+=1
            else:
                unsupported_panos_table.add_row(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7])

    for x in agent_list:
        if x[3] == "Supported Agent Version":
            supported_agent_table.add_row(x[0], x[1], x[2], x[3])

        else:
            unsupported_agent_table.add_row(x[0], x[1], x[2], x[3])

if supported_panos_table.row_count > 0:
    console.print(supported_panos_table)
    print("\n\n")
else:
    pass

if unsupported_panos_table.row_count > 0:
    console.print(unsupported_panos_table)
    print("\n\n")
else:
    pass

if ignore_panos_table.row_count > 0:
    console.print(ignore_panos_table)
    print("\n\n")
else:
    pass

if supported_agent_table.row_count > 0:
    console.print(supported_agent_table)
    print("\n\n")
else:
    pass

if unsupported_agent_table.row_count > 0:
    console.print(unsupported_agent_table)
    print("\n\n")
else:
    pass

agent_ip = list(set(agent_ip))
num_agents_checked = len(agent_ip)

agent_ip_failed = list(set(agent_ip_failed))
num_agents_failed = len(agent_ip_failed)

total_devices = list(set(total_devices))
num_total_devices = len(total_devices)

results_table = Table(title="Device Summary", show_header=True, header_style="bold magenta", show_lines=True, title_justify="center", show_edge=True)
results_table.add_column("Status", justify="center")
results_table.add_column("Device/Agent Count", justify="center")
results_table.add_row("Total Number of PANOS Devices", str(num_total_devices))
results_table.add_row("Total Number of Reachable Agents", str(num_agents_checked))

if reachable_count > 0:
    results_table.add_row("Number of PANOS Devices Checked", str(reachable_count))

if devices_no_agent > 0:
    results_table.add_row("Number of PANOS Devices without Agent", str(devices_no_agent))

if agents_checked > 0:
    results_table.add_row("Number of Agents Checked", str(num_agents_checked))

if not_reachable > 0:
    results_table.add_row("Number of PANOS Devices not reachable", str(not_reachable))

if agents_failed > 0:
    results_table.add_row("Number of Agents Not Reachable", str(num_agents_failed))

console.print(results_table)

if args.w:
    console.save_html(html_file)
    if args.o:
        webbrowser.open('file://'+os.path.dirname(os.path.realpath(__file__))+'/'+html_file, new = 2)
    else:
        pass

print("\n\n")
k=input("press Enter to exit")
