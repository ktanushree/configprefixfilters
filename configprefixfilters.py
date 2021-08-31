#!/usr/bin/env python
"""
Prisma SDWAN Config Prefix Filters.

tkamath@paloaltonetworks.com

Version: 1.0.0 b1
"""
# standard modules
import getpass
import json
import logging
import datetime
import os
import sys
import csv
import time
import pandas as pd

#standard modules
import argparse
import logging

# CloudGenix Python SDK
import cloudgenix
import codecs

# Global Vars
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Config Prefix Filter'
NOIP = 1
BADIP = 2
GOODIP = 3
ERROR = -99

APPEND="APPEND"
OVERWRITE = "OVERWRITE"

pf_name_id = {}
pf_id_name = {}
pf_id_pflist = {}
pf_id_pfdata = {}


# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)

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


def validIP(addr):

    if(addr):
        if addr == 'None':
            return NOIP
        else:
            octets = addr.split(".")
            if (len(octets) != 4):
                return BADIP

            for i in octets:
                if not 0 <= int(i) <=255:
                    return BADIP
    else:
        return NOIP

    return GOODIP


def create_dicts(cgx_session):
    print("Retrieving Global Prefix Filters")
    resp = cgx_session.get.globalprefixfilters()
    if resp.cgx_status:
        pflist = resp.cgx_content.get("items", None)
        for pf in pflist:
            pf_id_name[pf["id"]] = pf["name"]
            pf_name_id[pf["name"]] = pf["id"]
            pf_id_pfdata[pf["id"]] = pf
            filters = pf.get("filters",None)[0]
            if filters is not None:
                prefix = filters.get("ip_prefixes",None)
                pf_id_pflist[pf["id"]] = prefix
            else:
                pf_id_pflist[pf["id"]] = []

    return


def remove_bom(line):
    return line[3:] if line.startswith(codecs.BOM_UTF8) else line


def config_prefixfilter(csv_file_name,cgx_session,action):
    if os.path.exists(csv_file_name):
        csvdata = pd.read_csv(csv_file_name)
        namelist = csvdata.columns.values
        for name in namelist:
            prefixlist = csvdata[name].dropna().tolist()

            for prefix in prefixlist:
                tmp = prefix.split('/')
                ip = tmp[0]

                res = validIP(ip)
                if res == BADIP or res == ERROR:
                    print("WARN: Please check prefix {} for {}".format(prefix,name))

            if name in pf_name_id.keys():
                print("INFO: Prefix Filter {} exists".format(name))

                pfid = pf_name_id[name]
                data = pf_id_pfdata[pfid]
                configured_prefix = pf_id_pflist[pfid]

                if action == APPEND:
                    for prefix in prefixlist:
                        if prefix in configured_prefix:
                            print("\tWARN: {} already present in {}".format(prefix,name))
                            continue
                        else:
                            configured_prefix.append(prefix)

                    new_filters = [{"type": "ipv4", "ip_prefixes": configured_prefix}]
                    data["filters"] = new_filters

                else:
                    new_filters = [{"type": "ipv4", "ip_prefixes": prefixlist}]
                    data["filters"] = new_filters

                resp = cgx_session.put.globalprefixfilters(globalprefixfilter_id=pfid, data=data)
                if resp.cgx_status:
                    print("\tSUCCESS: {} Updated [{}]".format(name,action))

                else:
                    print("ERR: Could not update prefix filter {}".format(name))
                    cloudgenix.jd_detailed(resp)

            else:
                print("INFO: Creating Prefix Filter {}".format(name))
                payload = {
                    "name": name,
                    "description": None,
                    "filters": [{"type": "ipv4", "ip_prefixes": prefixlist}]}

                resp = cgx_session.post.globalprefixfilters(data=payload)
                if resp.cgx_status:
                    print("\tSUCCESS: {} Created".format(name))
                else:
                    print("ERR: Could not create prefix filter {}".format(name))
                    cloudgenix.jd_detailed(resp)

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
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)

    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)

    # Commandline for CSV file name
    pf_group = parser.add_argument_group('Prefix Filter CSV', 'CSV file containing prefix filters information')
    pf_group.add_argument("--filename", "-F", help="Name of the file with path.", default=None)
    pf_group.add_argument("--action", "-A", help="Action for existing Prefix Filters. APPEND will append prefixes to the existing list. OVERWRITE will overwrite with new values from the CSV",default="APPEND")

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)

    args = vars(parser.parse_args())

    if args['debug'] == 1:
        logging.basicConfig(level=logging.INFO,
                            format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
        logger.setLevel(logging.INFO)
    elif args['debug'] >= 2:
        logging.basicConfig(level=logging.DEBUG,
                            format="%(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s")
        logger.setLevel(logging.DEBUG)
    else:
        # Remove all handlers
        for handler in logging.root.handlers[:]:
            logging.root.removeHandler(handler)
        # set logging level to default
        logger.setLevel(logging.WARNING)

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

    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SDK_VERSION, cgx_session.controller))

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

    action = args["action"]
    if action not in [APPEND, OVERWRITE]:
        print("ERR: Invalid Action. Please pick from APPEND or OVERWRITE")
        cgx_session.get.logout()
        sys.exit()


    prefixfilter_csv = args['filename']
    if prefixfilter_csv is None:
        print("Please provide CSV filename with prefix filter information")
        cgx_session.get.logout()
        sys.exit()

    create_dicts(cgx_session)

    print("%s: Reading CSV %s and validating values for %s" % (curtime_str, prefixfilter_csv, tenant_str))
    config_prefixfilter(prefixfilter_csv, cgx_session, action)

    # end of script, run logout to clear session.
    print("Logging Out.")
    cgx_session.get.logout()


if __name__ == "__main__":
    go()