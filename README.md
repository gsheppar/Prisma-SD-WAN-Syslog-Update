# Prisma SD-WAN Syslog Update (Preview)
The purpose of this script is to update a local Syslog Server entry on an every Site ION (no Syslog Profiles). It matches based on Syslog Name and then updates any changes to the following

	syslog["name"] = "Demo"
    syslog["server_ip"] = "1.1.1.1"
    syslog["severity_level"] = "minor"
    syslog["server_port"] = 514
    syslog["enable_flow_logging"] = True 

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.7

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 1. ./Syslog.py
      - Will search every Site ION and update a Syslog entry if it finds a name match.

### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
