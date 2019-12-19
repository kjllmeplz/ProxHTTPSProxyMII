#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"Cert Tools, pyOpenSSL version"

__author__ = 'phoenix'
__version__ = '0.2'

CA = "CA.crt"
CERTDIR = "Certs"
# Temp list for generating certs
workingList = set()

import os
import time
import OpenSSL
import ipaddress

def create_CA(capath):
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)
    ca = OpenSSL.crypto.X509()
    ca.set_serial_number(0)
    # Value 2 means v3
    ca.set_version(2)
    subj = ca.get_subject()
    subj.countryName = 'CN'
    subj.organizationName = 'ProxHTTPSProxy'
    subj.organizationalUnitName = 'pyOpenSSL'
    subj.commonName = 'ProxHTTPSProxy CA'
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(24 * 60 * 60 * 730)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions(
        [OpenSSL.crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
         # mozilla::pkix doesn't handle the Netscape Cert Type extension (which is problematic when it's marked critical)
         # https://bugzilla.mozilla.org/show_bug.cgi?id=1009161
         OpenSSL.crypto.X509Extension(b"nsCertType", False, b"sslCA"),
         OpenSSL.crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth,clientAuth,emailProtection,timeStamping,msCodeInd,msCodeCom,msCTLSign,msSGC,msEFS,nsSGC"),
         OpenSSL.crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
         OpenSSL.crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca)])
    ca.sign(key, 'sha256')
    with open(capath, 'wb') as fp:
        fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, ca))
        fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
    
def get_cert(name, cafile=CA, certdir=CERTDIR):
    """Return cert file path. Create it if it doesn't exist.

    cafile: the CA file to create dummpy cert files
    certdir: the path where cert files are looked for or created
    """
    certfile = os.path.join(certdir, name + '.crt')
    if not os.path.exists(certfile):
        dummy_cert(cafile, certfile, name)
    return certfile

def dummy_cert(cafile, certfile, commonname):
    """Generates and writes a certificate to certfile
    commonname: Common name for the generated certificate
    Ref: https://github.com/mitmproxy/netlib/blob/master/netlib/certutils.py
    """
    if certfile in workingList:
        # Another thread is working on it, wait until it finish
        while True:
            time.sleep(0.2)
            if certfile not in workingList: break
    else:
        workingList.add(certfile)
        with open(cafile, "rb") as file:
            content = file.read()
            ca = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, content)
            key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, content)
        cert = OpenSSL.crypto.X509()
        cert.set_version(2)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(63072000)
        cert.set_issuer(ca.get_subject())
        try:
            ip = ipaddress.ip_address(commonname)
            cert.get_subject().CN = commonname
            san = 'IP: ' + commonname
            cert.add_extensions([OpenSSL.crypto.X509Extension(b"subjectAltName", False, san.encode())])
        except ValueError:
            # protocol limits common name field to 64 characters.
            # commonnameshort may use wildcard to 'shorten' commonname.
            i = commonname.count('.')
            commonname_temp = commonname
            while True:
                if len(commonname_temp) <= 64:
                    if commonname_temp.count('.') < 2 or len(commonname_temp) > 62:
                        commonnameshort = commonname_temp
                    else:
                        commonnameshort = '*.' + commonname_temp.partition('.')[-1]
                    cert.get_subject().CN = commonnameshort
                    san = 'DNS: ' + commonname_temp
                    cert.add_extensions([OpenSSL.crypto.X509Extension(b"subjectAltName", False, san.encode())])
                    break
                else:
                    i = i - 1
                    if i < 1:   
                        print('Address too long')
                        break
                    commonname_temp = commonname_temp.partition('.')[-1]
                    continue
        except:
            print('Address not found')
        cert.set_serial_number(int(time.time()*10000))
        cert.set_pubkey(ca.get_pubkey())
        cert.sign(key, "sha256")
        with open(certfile, 'wb') as fp:
            fp.write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
            fp.write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))
        workingList.remove(certfile)

def startup_check():
    if not os.path.exists(CERTDIR):
        os.mkdir(CERTDIR)
        if not os.path.exists(CERTDIR):
            print("%s directory does not exist!")
            print("Please create it and restart the program!")
            input()
            raise SystemExit

    if not os.path.exists(CA):
        print("Creating CA ...")
        create_CA(CA)
        if not os.path.exists(CA):
            print("Failed to create CA :(")
        else:
            print("* Please import created %s to your client's store of trusted certificate authorities." % CA)
            print("* Please delete all files under %s directory!" % CERTDIR)
            print("* Then restart the program!")
        input()
        raise SystemExit

startup_check()

if __name__ == "__main__":
    print("All Good!")
