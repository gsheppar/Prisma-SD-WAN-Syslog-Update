#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed, jdout
import yaml
import cloudgenix_settings
import sys
import logging
import ipcalc
import os
import datetime
from csv import DictReader
import ipcalc


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example syslog script'
SCRIPT_VERSION = "v1"

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

def update(cgx, syslog):
    elem_resp = cgx.get.elements()
    elem_list = elem_resp.cgx_content.get('items', None)
    
    for site in cgx.get.sites().cgx_content['items']:
        for element in cgx.get.elements().cgx_content['items']:
            elem_id = element['id']
            name = element['name']
            sid = element['site_id']
            model_name = element['model_name']
            if element['site_id'] == site["id"]:
                if name == None:
                    name = "Unamed device"
                resp = cgx.get.syslogservers(site_id=sid,element_id=elem_id)
                item_list = resp.cgx_content.get('items', None)
                syslog_found = False
                for syslog_data in item_list:
                    if syslog_data['name'] == syslog["name"]:
                        update_syslog = False
                        syslog_found = True
                        if syslog_data['server_ip'] != syslog["server_ip"]:
                            update_syslog = True
                            syslog_data['server_ip'] = syslog["server_ip"]
                        if syslog_data['severity_level'] != syslog['severity_level']:
                            update_syslog = True
                            syslog_data['severity_level'] = syslog["severity_level"]
                        if syslog_data['enable_flow_logging'] != syslog['enable_flow_logging']:
                            update_syslog = True
                            syslog_data['enable_flow_logging'] = syslog['enable_flow_logging']
                        if syslog_data['server_port'] != syslog['server_port']:
                            update_syslog = True
                            syslog_data['server_port'] = syslog['server_port']
                        if update_syslog:
                            syslog_id = syslog_data['id']
                            resp = cgx.put.syslogservers(site_id=sid, element_id=elem_id, syslogserver_id=syslog_id, data=syslog_data)
                            if not resp:
                                print("Error updating Syslog " + syslog_data['name'] +" on " + name)
                                print(str(jdout(resp)))
                                return
                            print("Updating Syslog " + syslog_data['name'] +" on " + name)
                        else:
                            print("Syslog " + syslog_data['name'] +" on " + name + " already updated")
                    if not syslog_found:
                        print("Syslog " + syslog['name'] +" on " + name + " is not present")
    return
                                 
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    # Allow Controller modification and debug level sets.
    config_group = parser.add_argument_group('Config', 'These options change how the configuration is generated.')
    config_group.add_argument("--destroy", help="DESTROY Syslog name",
                              default=False, action="store_true")
                             
    args = vars(parser.parse_args())
    destroy = args['destroy']
    
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    syslog = {}
    syslog["name"] = "Test1234"
    syslog["server_ip"] = "1.1.1.1"
    syslog["severity_level"] = "minor"
    syslog["server_port"] = 514
    syslog["enable_flow_logging"] = True

    
    update(cgx, syslog) 
    # end of script, run logout to clear session.
    print("End of script. Logout!")
    cgx_session.get.logout()

if __name__ == "__main__":
    go()