import urllib2
import sys
import re
import base64
from urlparse import urlparse
import os
import getopt

def get_cpanel_version():
    with open('/usr/local/cpanel/version', 'r') as cp_version_file:
        cp_version = cp_version_file.read(5)
        cp_version_file.close()
        return cp_version

def get_api_token():
    if os.path.exists('/root/.ngcp_api_token'):
        with open('/root/.ngcp_api_token', 'r') as ngcp_api_token_file:
            ngcp_api_token = ngcp_api_token_file.read().replace('\n', '')
            ngcp_api_token_file.close()

            if not ngcp_api_token:
                raise Exception('ngcp_api_token API Token is empty. Please fill with "username:token"')
            else:
                return ngcp_api_token
    else:
        raise Exception('ngcp_api_token API Token file does not exist. Please fill with "username:token"')

def api(arg):

        cp_version = get_cpanel_version()
	# cPanel & WHM version 66 deprecated XML output for cPanel API 1, cPanel API 2, UAPI, WHM API 0, and WHM API 1.
	if cp_version >= "11.66":
		theurl = 'http://127.0.0.1:2086/json-api/' + arg
	else:
		theurl = 'http://127.0.0.1:2086/xml-api/' + arg

	if cp_version >= "11.68":
                auth = 'whm ' + get_api_token()
	else:
		if os.path.exists('/root/.accesshash'):
			hash = open("/root/.accesshash", 'r')
			hashstring = hash.read()
			hashstring = hashstring.replace('\n', '')

			auth = 'WHM root:' + hashstring
		else:
			print "Access key doesn't exist, Please Generate it in WHM"
			sys.exit(1)

	req = urllib2.Request(theurl)

	req.add_header("Authorization", auth)
	try:
		handle = urllib2.urlopen(req)
	except IOError, e:
		print 'Error: ', e
		print "The Access key found but It looks like logins not working, Please regenerate it in WHM."
		sys.exit(1)

	return handle.read() # Output page result
