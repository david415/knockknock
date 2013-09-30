#!/usr/bin/env python
__author__ = "Moxie Marlinspike"
__email__  = "moxie@thoughtcrime.org"
__license__= """
Copyright (c) 2009 Moxie Marlinspike <moxie@thoughtcrime.org>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

import time, os, sys
import getopt
import subprocess
import nacl.secret
import nacl.utils
from scapy.all import send, IP, TCP, hexdump
from struct import *

from knockknock.Profile import Profile




def usage():
    print "Usage: knockknock.py -p <portToOpen> <host>"
    sys.exit(2)
    
def parseArguments(argv):
    try:
        port       = 0
        host       = ""
        opts, args = getopt.getopt(argv, "h:p:")
        
        for opt, arg in opts:
            if opt in ("-p"):
                port = arg
            else:
                usage()
                
        if len(args) != 1:
            usage()
        else:
            host = args[0]

    except getopt.GetoptError:           
        usage()                          

    if port == 0 or host == "":
        usage()

    return (port, host)

def getProfile(host):
    homedir = os.path.expanduser('~')
    
    if not os.path.isdir(homedir + '/.knockknock/'):
        print "Error: you need to setup your profiles in " + homedir + '/.knockknock/'
        sys.exit(2)

    if not os.path.isdir(homedir + '/.knockknock/' + host):
        print 'Error: profile for host ' + host + ' not found at ' + homedir + '/.knockknock/' + host
        sys.exit(2)

    return Profile(homedir + '/.knockknock/' + host)

def verifyPermissions():
    if os.getuid() != 0:
        print 'Sorry, you must be root to run this.'
        sys.exit(2)    

def existsInPath(command):
    def isExe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    for path in os.environ["PATH"].split(os.pathsep):
        exeFile = os.path.join(path, command)
        if isExe(exeFile):
            return exeFile

    return None

def main(argv):
    (port, host) = parseArguments(argv)
    verifyPermissions()
    
    profile      = getProfile(host)
    knockPort    = profile.getKnockPort()

    counter      = profile.loadCounter()
    counter      = counter + 1
    nonce        = pack('LLL', 0,0,counter)
    port         = pack('H', int(port))

    ciphertext   = profile.encrypt(port, nonce)    
    packetData   = ciphertext[nacl.secret.nacl.lib.crypto_secretbox_NONCEBYTES:]

    # use scapy to send data in syn packet header

    (idField, seqField, ackField, winField, opt1, opt2, opt3, opt4, opt5, opt6) = unpack('!HIIHcccccc', packetData)

    hexdump(packetData)

    tcp = TCP(dport   = int(knockPort), 
              flags   = 'S',
              seq     = seqField,
              ack     = ackField,
              window  = winField,
              options = [('MSS', pack('cccccc', opt1, opt2, opt3, opt4, opt5, opt6))] )

    ip = IP(dst=host, id=idField)

    ip.show()
    tcp.show()

    send(ip/tcp)

    profile.storeCounter(counter)


if __name__ == '__main__':
    main(sys.argv[1:])
