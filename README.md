# ![alt text](https://github.com/rlemm-pan/userid-check/blob/main/palo.ico?raw=true) userid-check
This tool empowers you to effortlessly determine the PAN-OS Version and User-ID/Terminal Server Agent Version currently running on your Palo Alto Networks devices and UserID/Terminal Server Agents. The primary objective is to ensure that your devices operate on a PAN-OS and Agent version unaffected by the expiration of certificates on November 18th, 2024.  For further details, please refer to this link below:

### [Certificate Expiration on November 18, 2024](https://live.paloaltonetworks.com/t5/customer-advisories/update-to-additional-pan-os-certificate-expirations-and-new/ta-p/572158)

Before we dive in, let's go over the prerequisites for using this tool. First, make sure you're running Python version 3.x or greater on the host you will be using to run this tool. Second, create a text file containing the IP addresses of your PANOS Next Generation Firewalls and Panorama devices. Save this file in the same location where you'll run the Self Impact Discovery Tool.  Below is an Example:

```
192.168.1.1
10.1.1.1
172.16.1.1
```
Any text editor will do as long as you save it in basic text format.  If there are any errors in the file, (ie extra carriage returns, invalid IP's) the tool will tell you and skip them.  Do not use FQDN's.  IP Addresses only.

# Logic Flowchart

![alt text](https://github.com/rlemm-pan/userid-check/blob/main/flowchart.png?raw=true)

![alt text](https://github.com/rlemm-pan/userid-check/blob/main/SUPPORT.md)
# Considerations:

1.  Endpoint where the tool is installed should have access/reachability to all IP's in the text file and Agents discovered.
2.  The tool does make SSL/TLS Calls to the Agents to determine the Certificate Expiration Date.
3.  The Terminal Server Agent does not report its current version correctly.  This is a known issue.  However, the tool is correctly determining if you are affected by making the SSL/TLS call to the Terminal Server Agent.
4.  No changes are made to your devices with this tool.  The tool only gathers info using API and SSL calls to the devices listed in your text file and agents discovered on your PANOS Devices.
5.  If you have affected PANOS devices and Agents, you should consider upgrading your PANOS Devices before upgrading your agents.  If the Agent is upgraded before the PANOS device is upgraded, connectivity will be lost to PANOS Devices running an affected PANOS version.  So, to ensure connectivity is maintained during and after the upgrade process, the order of operation should be to upgrade the PANOS devices, then the Agents last.


## Step 1:

Download the tool from this site by clicking on the Green Button in the Upper Right-Hand corner labeled "Code." Next, click on "Download ZIP." This action will download everything you need to proceed to the following steps.

https://github.com/rlemm-pan/userid-check/blob/main

## Step 2:

Once downloaded to a folder of your choice, extract the file into that folder. Open a terminal window or CLI on your platform, navigate to the folder where you extracted the tool, and run the following command:

```console
pip3 install -r requirements.txt
```
## or

```console
pip install -r requirements.txt
```

## Note for Windows Users:

If you are running Microsoft Windows 10, you may need to run the following commands as well:

```console
python3 -m pip install --upgrade --user urllib3
python3 -m pip install
```
## or
```console
python -m pip install --upgrade --user urllib3
python -m pip install
```
## Step 3

After installing the requirements, type the following command:
```console
python3 userid-check.py -h

usage: userid-check.py [-h] [-x] [-w [W]] [-o] [-c] [-n [N]]

Usage Examples:

	python3 redist-check.py -x

	python3 redist-check.py -x -w

	python3 redist-check.py -x -o -w

	python3 redist-check.py -c -x -o -w

	python3 redist-check.py -x -w yourfile.html

	python3 redist-check.py -x -o -w yourfile.html

	python3 redist-check.py -c -x -o -w yourfile.html

	python3 redist-check.py -c -x -o -w -n

	python3 redist-check.py -c -x -o -w yourfile.html -n yourdiagram.png

optional arguments:
  -h, --help  show this help message and exit
  -x          Optional - Disable Links Pop-Up
  -w [W]      Optional - Create WebPage from output.  If no file is specified after '-w', then 'output.html' will be used
  -o          Requires '-w' - Open Results in Web Browser
  -c          Writes CSV (2 total)
  -n [N]      Optional - Create Relational Diagram of Devices and Agents.  If no file is specified after '-n', then 'diagram.png' will be used

```

This will display usage examples and different argument options available for this tool:

'-x' argument will suppress the Pop-Up Links for the Advisory at the beginning.

'-w' argument will create an HTML file of the results.  You can specify an HTML filename if desired.

'-o' argument will open the HTML file in your browser at completion.

'-c' argument will create csv files at completion.

'-n' argument will add a Relational Diagram to the HTML file.  You can specify a PNG filename if desired.

### These arguments are optional and not required.

## Step 4

Run the following command. If you wish to use any of the argument options mentioned earlier, please add those to your command:

```
python3 userid-check.py
```
## or
```
python userid-check.py
```
You'll be prompted to enter the name of the text file you created earlier and your credentials. Ensure you use credentials with API access rights. MFA credentials will not work with this tool. Use a common local service account; superuser rights are not necessary, readonly-superuser will work.

Once the tool finishes running, you'll see results with different colors. Green indicates no action is needed, yellow means action is required based on the advisory explained in the links on this GitRepo and no color means the devices are not configured with Agents and are for informational purposes only.  If the '-n' option is selected, a relational diagram of your affected PANOS Devices and Agents will be created and added to the HTML output for reference.  

## Sample output of HTML and relational diagram:

![alt text](https://github.com/rlemm-pan/userid-check/blob/main/example.png?raw=true)


Additionally, there's a webpage in the tool you can access in the same folder. The file is called PANOS_Recommend.html. Open this file with your chosen browser, and a page will appear that you can use to check any other PAN-OS Version you may be running. This webpage is designed for PANOS only, not the Agent Versions.  Below is a screenshot of the web page:


![alt text](https://github.com/rlemm-pan/userid-check/blob/main/webpage_example.png?raw=true)
