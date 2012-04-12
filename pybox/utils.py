#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Some useful utilities.
"""

__author__ = "Hui Zheng"
__copyright__ = "Copyright 2011-2012 Hui Zheng"
__credits__ = ["Hui Zheng"]
__license__ = "MIT <http://www.opensource.org/licenses/mit-license.php>"
__version__ = "0.1"
__maintainer__ = "Hui Zheng"
__email__ = "xyzdll[AT]gmail[DOT]com"
__status__ = "Development"

import os
import sys

import cookielib
import hashlib 
import logging
import logging.config
import mechanize
import xml.etree.ElementTree
try: 
    import xml.etree.cElementTree as etree
except ImportError: 
    import xml.etree.ElementTree as etree

ENCODING = sys.stdin.encoding # typically "UTF-8"

def is_posix():
    return os.name == 'posix'

def get_sha1(file):
    """Get SHA1 for a file"""
    with open(file) as f:
        h = hashlib.sha1() 
        h.update(f.read()) 
        return h.hexdigest() 

def encode(unicode):
    """Encode the given unicode as stdin's encoding"""
    return unicode.encode(ENCODING)

def print_unicode(unicode):
    """Print the given unicode string as stdin's encoding"""
    print encode(unicode)

def get_logger(name, conf_name="logging.conf"):
    """Return a logger with the given name from the given configuration file"""
    env_var = "LOG_CONF_DIR"
    log_dir = os.getenv(env_var) or "."
    log_path = os.path.join(log_dir, conf_name)
    if not os.path.exists(log_path):
        sys.stderr.write("log configuration file {} does NOT exist\n"
                .format(log_path))
        exit(1)

    try:
        logging.config.fileConfig(log_path)
        return logging.getLogger(name)
    except Exception as e:
        sys.stderr.write("exception: {}\n".format(e))
        exit(1)

def parse_xml(source):
    """Parse an XML source into an element tree"""
    return etree.parse(source).getroot()

def stringify(obj):
    """Turn an object to a readable string(in default encoding)"""
    if xml.etree.ElementTree.iselement(obj):
        return etree.tostring(obj, ENCODING)

    if hasattr(obj, '__iter__'):
        return encode(repr(obj).decode('raw_unicode_escape'))

    try:
        return str(obj)
    except UnicodeError:
        return encode(obj)

def map_element(element):
    """Convert an XML element to a map"""
    #if sys.version_info >= (2, 7):
        #return {e.tag: e.text.strip() for e in list(element)}
    #return dict((e.tag, e.text and e.text.strip() or "") for e in list(element))
    return dict((e.tag, e.text) for e in list(element))

def get_browser(debug=False):
    """Gets a browser for automating interaction"""
    browser = mechanize.Browser()

    # Cookie Jar
    cj = cookielib.LWPCookieJar()
    browser.set_cookiejar(cj)

    # Browser options
    browser.set_handle_equiv(True)
    #browser.set_handle_gzip(True)
    browser.set_handle_redirect(True)
    browser.set_handle_referer(True)
    browser.set_handle_robots(False) # important, otherwise will be rejected by robots.txt

    # Follows refresh 0 but not hangs on refresh > 0
    browser.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(), max_time=1)

    browser.set_debug_http(debug)
    browser.set_debug_redirects(debug)
    browser.set_debug_responses(debug)

    browser.addheaders = [('User-agent', "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:7.0.1) Gecko/20100101 Firefox/7.0.1") ]
    return browser

def decode_args(args, options):
    """Convert args and options to unicode string"""
    for attr, value in options.__dict__.iteritems():
        if isinstance(value, str):
            setattr(options, attr, value.decode(ENCODING))
    return [arg.decode(ENCODING) for arg in args]

