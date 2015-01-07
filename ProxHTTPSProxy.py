#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"A Proxomitron Helper Program"

_name = 'ProxHTTPSProxyMII'
__author__ = 'phoenix'
__version__ = 'v1.2'

CONFIG = "config.ini"
CA_CERTS = "cacert.pem"

import os
import time
import configparser
import fnmatch
import logging
import threading
import ssl
import urllib3
#https://urllib3.readthedocs.org/en/latest/security.html#insecurerequestwarning
urllib3.disable_warnings()

from socketserver import ThreadingMixIn
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse
from ProxyTool import ProxyRequestHandler, get_cert

from colorama import init, Fore, Back, Style
init(autoreset=True)

class LoadConfig:
    def __init__(self, configfile):
        self.config = configparser.ConfigParser(allow_no_value=True,
                                                inline_comment_prefixes=('#',))
        self.config.read(configfile)
        self.PROXADDR = self.config['GENERAL'].get('ProxAddr')
        self.FRONTPORT = int(self.config['GENERAL'].get('FrontPort'))
        self.REARPORT = int(self.config['GENERAL'].get('RearPort'))
        self.DEFAULTPROXY = self.config['GENERAL'].get('DefaultProxy')
        self.LOGLEVEL = self.config['GENERAL'].get('LogLevel')

class ConnectionPools:
    """
    self.pools is a list of {'proxy': 'http://127.0.0.1:8080',
                             'pool': urllib3.ProxyManager() object,
                             'patterns': ['ab.com', 'bc.net', ...]}
    self.getpool() is a method that returns pool based on host matching
    """
    # Windows default CA certificates are incomplete 
    # See: http://bugs.python.org/issue20916
    # cacert.pem sources:
    # - http://curl.haxx.se/docs/caextract.html
    # - http://certifi.io/en/latest/

    # ssl_version="TLSv1" to specific version
    sslparams = dict(cert_reqs="REQUIRED", ca_certs=CA_CERTS)
    # IE: http://support2.microsoft.com/kb/181050/en-us
    # Firefox about:config
    # network.http.connection-timeout 90
    # network.http.response.timeout 300
    timeout = urllib3.util.timeout.Timeout(connect=90.0, read=300.0)

    def __init__(self, config):
        self.file = config
        self.file_timestamp = os.path.getmtime(config)
        self.loadConfig()

    def loadConfig(self):
        # self.conf has to be inited each time for reloading
        self.conf = configparser.ConfigParser(allow_no_value=True, delimiters=('=',),
                                              inline_comment_prefixes=('#',))
        self.conf.read(self.file)
        self.pools = []
        proxy_sections = [section for section in self.conf.sections()
                          if section.startswith('PROXY')]
        for section in proxy_sections:
            proxy = section.split()[1]
            self.pools.append(dict(proxy=proxy,
                                   # maxsize is the max. number of connections to the same server
                                   pool=[urllib3.ProxyManager(proxy, 10, maxsize=8, timeout=self.timeout, **self.sslparams),
                                         urllib3.ProxyManager(proxy, 10, maxsize=8, timeout=self.timeout)],
                                   patterns=list(self.conf[section].keys())))
        default_proxy = self.conf['GENERAL'].get('DefaultProxy')
        default_pool = ([urllib3.ProxyManager(default_proxy, 10, maxsize=8, timeout=self.timeout, **self.sslparams),
                         urllib3.ProxyManager(default_proxy, 10, maxsize=8, timeout=self.timeout)]
                        if default_proxy else
                        [urllib3.PoolManager(10, maxsize=8, timeout=self.timeout, **self.sslparams),
                         urllib3.PoolManager(10, maxsize=8, timeout=self.timeout)])
        self.pools.append({'proxy': default_proxy, 'pool': default_pool, 'patterns': '*'})

        self.noverifylist = list(self.conf['SSL No-Verify'].keys())
        self.blacklist = list(self.conf['BLACKLIST'].keys())
        self.sslpasslist = list(self.conf['SSL Pass-Thru'].keys())
        self.bypasslist = list(self.conf['BYPASS URL'].keys())

    def reloadConfig(self):
        while True:
            mtime = os.path.getmtime(self.file)
            if mtime > self.file_timestamp:
                self.file_timestamp = mtime
                self.loadConfig()
                logger.info(Fore.RED + Style.BRIGHT
                             + "*" * 20 + " CONFIG RELOADED " + "*" * 20)
            time.sleep(1)

    def getpool(self, host, httpmode=False):
        noverify = True if httpmode or any((fnmatch.fnmatch(host, pattern) for pattern in self.noverifylist)) else False
        for pool in self.pools:
            if any((fnmatch.fnmatch(host, pattern) for pattern in pool['patterns'])):
                return pool['proxy'], pool['pool'][noverify], noverify

class FrontServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass

class RearServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    pass

class FrontRequestHandler(ProxyRequestHandler):
    """
    Sit between the client and Proxomitron
    Convert https request to http
    """
    server_version = "%s FrontProxy/%s" % (_name, __version__)

    def do_CONNECT(self):
        "Descrypt https request and dispatch to http handler"
        # request line: CONNECT www.example.com:443 HTTP/1.1
        self.host, self.port = self.path.split(":")
        self.proxy, self.pool, self.noverify = pools.getpool(self.host)
        if any((fnmatch.fnmatch(self.host, pattern) for pattern in pools.blacklist)):
            # BLACK LIST
            self.deny_request()
            logger.info(Fore.CYAN + 'Denied by blacklist: %s' % self.host)
        elif any((fnmatch.fnmatch(self.host, pattern) for pattern in pools.sslpasslist)):
            # SSL Pass-Thru
            if self.proxy and self.proxy.startswith('https'):
                self.forward_to_https_proxy()
            elif self.proxy and self.proxy.startswith('socks5'):
                self.forward_to_socks5_proxy()
            else:
                self.tunnel_traffic()
            # Upstream server or proxy of the tunnel is closed explictly, so we close the local connection too
            self.close_connection = 1
        else:
            # SSL MITM
            self.wfile.write(("HTTP/1.1 200 Connection established\r\n" +
                              "Proxy-agent: %s\r\n" % self.version_string() +
                              "\r\n").encode('ascii'))
            commonname = '.' + self.host.partition('.')[-1] if self.host.count('.') >= 2 else self.host
            dummycert = get_cert(commonname)
            # set a flag for do_METHOD
            self.ssltunnel = True

            ssl_sock = ssl.wrap_socket(self.connection, keyfile=dummycert, certfile=dummycert, server_side=True)
            # Ref: Lib/socketserver.py#StreamRequestHandler.setup()
            self.connection = ssl_sock
            self.rfile = self.connection.makefile('rb', self.rbufsize)
            self.wfile = self.connection.makefile('wb', self.wbufsize)
            # dispatch to do_METHOD()
            self.handle_one_request()

    def do_METHOD(self):
        "Forward request to Proxomitron"
        if self.ssltunnel:
            # https request
            host = self.host if self.port == '443' else "%s:%s" % (self.host, self.port)
            url = "https://%s%s" % (host, self.path)
            self.bypass = any((fnmatch.fnmatch(url, pattern) for pattern in pools.bypasslist))
            if not self.bypass:
                url = "http://%s%s" % (host, self.path)
                # Tag the request so Proxomitron can recognize it
                self.headers["Tagged"] = self.version_string()
        else:
            # http request
            self.host = urlparse(self.path).hostname
            if any((fnmatch.fnmatch(self.host, pattern) for pattern in pools.blacklist)):
                # BLACK LIST
                self.deny_request()
                logger.info(Fore.CYAN + 'Denied by blacklist: %s' % self.host)
                return
            host = urlparse(self.path).netloc
            self.proxy, self.pool, self.noverify = pools.getpool(self.host, httpmode=True)
            self.bypass = any((fnmatch.fnmatch('http://' + host + urlparse(self.path).path, pattern) for pattern in pools.bypasslist))
            url = self.path
        self.url = url
        prefix = '[P]' if self.proxy else '[D]'
        if self.bypass:
            prefix += '[B]'
        pool = self.pool if self.bypass else proxpool
        data_length = self.headers.get("Content-Length")
        self.postdata = self.rfile.read(int(data_length)) if data_length else None
        # Remove hop-by-hop headers
        self.purge_headers(self.headers)
        # pool.urlopen() expects a dict like headers container for http request
        headers = urllib3._collections.HTTPHeaderDict()
        [headers.add(key, value) for (key, value) in self.headers.items()]
        r = None
        try:
            # Sometimes 302 redirect would fail with "BadStatusLine" exception, and IE11 doesn't restart the request.
            # retries=1 instead of retries=False fixes it.
            r = pool.urlopen(self.command, url, body=self.postdata, headers=headers,
                             retries=1, redirect=False, preload_content=False, decode_content=False)
            if not self.ssltunnel:
                logger.info(Fore.GREEN + '%s "%s %s %s" %s %s' %
                            (prefix, self.command, url, self.request_version, r.status, r.getheader('Content-Length', '-')))

            self.send_response_only(r.status, r.reason)
            # HTTPResponse.getheader() combines multiple same name headers into one
            # https://login.yahoo.com would fail to login
            # Use HTTPResponse.msg instead
            r.headers = r._original_response.msg
            self.write_headers(r.headers)

            if self.command == 'HEAD' or r.status in (100, 101, 204, 304):
                written = None
            else:
                written = self.stream_to_client(r)
                if "Content-Length" not in r.headers and 'Transfer-Encoding' not in r.headers:
                    self.close_connection = 1

        # Intend to catch regular http and bypass http/https requests exceptions
        # Regular https request exceptions should be handled by rear server
        except urllib3.exceptions.TimeoutError as e:
            self.sendout_error(url, 504, message="Timeout", explain=e)
            logger.warning(Fore.YELLOW + '[F] %s on "%s %s"', e, self.command, url)
        except (urllib3.exceptions.HTTPError,) as e:
            self.sendout_error(url, 502, message="HTTPError", explain=e)
            logger.warning(Fore.YELLOW + '[F] %s on "%s %s"', e, self.command, url)
        finally:
            if r:
                # Release the connection back into the pool
                r.release_conn()

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_METHOD

class RearRequestHandler(ProxyRequestHandler):
    """
    Supposed to be the parent proxy for Proxomitron for tagged requests
    Convert http request to https
    
    """
    server_version = "%s RearProxy/%s" % (_name, __version__)
    
    def do_METHOD(self):
        "Convert http request to https"
        # request line: GET http://somehost.com/path?attr=value HTTP/1.1
        url = "https" + self.path[4:]
        self.host = urlparse(self.path).hostname
        proxy, pool, noverify = pools.getpool(self.host)
        prefix = '[P]' if proxy else '[D]'
        data_length = self.headers.get("Content-Length")
        self.postdata = self.rfile.read(int(data_length)) if data_length else None
        self.purge_headers(self.headers)
        # Remove the tag
        del self.headers["Tagged"]
        # pool.urlopen() expects a dict like headers container for http request
        headers = urllib3._collections.HTTPHeaderDict()
        [headers.add(key, value) for (key, value) in self.headers.items()]
        r = None
        try:
            r = pool.urlopen(self.command, url, body=self.postdata, headers=headers,
                             retries=1, redirect=False, preload_content=False, decode_content=False)
            if proxy:
                logger.debug('Using Proxy - %s' % proxy)
            color = Fore.RED if noverify else Fore.GREEN
            logger.info(color + '%s "%s %s" %s %s' %
                        (prefix, self.command, url, r.status, r.getheader('Content-Length', '-')))

            self.send_response_only(r.status, r.reason)
            # HTTPResponse.getheader() combines multiple same name headers into one
            # https://login.yahoo.com would fail to login
            # Use HTTPResponse.msg instead
            r.headers = r._original_response.msg
            self.write_headers(r.headers)
            
            if self.command == 'HEAD' or r.status in (100, 101, 204, 304):
                written = None
            else:
                written = self.stream_to_client(r)
                if "Content-Length" not in r.headers and 'Transfer-Encoding' not in r.headers:
                    self.close_connection = 1

        except urllib3.exceptions.SSLError as e:
            self.sendout_error(url, 417, message="SSL Certificate Failed", explain=e)
            logger.error(Fore.RED + Style.BRIGHT + "[SSL Certificate Error] " + url)
        except urllib3.exceptions.TimeoutError as e:
            self.sendout_error(url, 504, message="Timeout", explain=e)
            logger.warning(Fore.YELLOW + '[R] %s on "%s %s"', e, self.command, url)
        except (urllib3.exceptions.HTTPError,) as e:
            self.sendout_error(url, 502, message="HTTPError", explain=e)
            logger.warning(Fore.YELLOW + '[R] %s on "%s %s"', e, self.command, url)
        finally:
            if r:
                # Release the connection back into the pool
                r.release_conn()

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = do_METHOD

"""
#Information#

* Python default ciphers: http://bugs.python.org/issue20995
* SSL Cipher Suite Details of Your Browser: https://cc.dcsec.uni-hannover.de/
* https://wiki.mozilla.org/Security/Server_Side_TLS
"""

try:
    if os.name == 'nt':
        import ctypes
        ctypes.windll.kernel32.SetConsoleTitleW('%s %s' % (_name, __version__))

    config = LoadConfig(CONFIG)

    logger = logging.getLogger(__name__)
    logger.setLevel(getattr(logging, config.LOGLEVEL, logging.INFO))
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(message)s', datefmt='[%H:%M:%S]')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    pools = ConnectionPools(CONFIG)
    proxpool = urllib3.ProxyManager(config.PROXADDR, 10, maxsize=8,
                                    # A little longer than timeout of rear pool
                                    # to avoid trigger front server exception handler
                                    timeout=urllib3.util.timeout.Timeout(connect=90.0, read=310.0))

    frontserver = FrontServer(('', config.FRONTPORT), FrontRequestHandler)
    rearserver = RearServer(('', config.REARPORT), RearRequestHandler)
    for worker in (frontserver.serve_forever, rearserver.serve_forever,
                   pools.reloadConfig):
          thread = threading.Thread(target=worker)
          thread.dameon = True
          thread.start()

    print("=" * 76)
    print('%s %s (urllib3/%s)' % (_name, __version__, urllib3.__version__))
    print()
    print('  FrontServer  : localhost:%s' % config.FRONTPORT)
    print('  RearServer   : localhost:%s' % config.REARPORT)
    print('  ParentServer : %s' % config.DEFAULTPROXY)
    print('  Proxomitron  : ' + config.PROXADDR)
    print("=" * 76)
except KeyboardInterrupt:
    print("Quitting...")
