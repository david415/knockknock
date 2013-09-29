# Copyright (c) 2009 Moxie Marlinspike
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA
#

import os, string
import ConfigParser
import binascii
import stat
from struct import *
import nacl.secret
import binascii
from scapy.all import hexdump
from nacl.exceptions import CryptoError

class Profile:

    def __init__(self, directory, cipherKey=None, knockPort=None):
        self.counterFile  = None
        self.directory    = directory
        self.name         = directory.rstrip('/').split('/')[-1]

        if (cipherKey == None):
            self.deserialize()
        else:
            self.cipherKey = cipherKey
            self.knockPort = knockPort

        self.box = nacl.secret.SecretBox(self.cipherKey)

    def deserialize(self):
        self.cipherKey    = self.loadCipherKey()
        self.knockPort    = self.loadConfig()

    def serialize(self):
        self.storeCipherKey()
        self.storeConfig()
        self.storeCounter()

    # Getters And Setters

    def getIPAddrs(self):
        return self.ipAddressList

    def setIPAddrs(self, ipAddressList):
        self.ipAddressList = ipAddressList        

    def getName(self):
        return self.name

    def getDirectory(self):
        return self.directory

    def getKnockPort(self):
        return self.knockPort

    def storeCounter(self, counter):
        counterFile = open(self.directory + '/counter', 'w')
        self.setPermissions(self.directory + '/counter')

        counterFile.seek(0)
        counterFile.write(str(counter) + "\n")
        counterFile.flush()
        counterFile.close()

    def loadCounter(self):
        # Privsep bullshit...
        counterFile = open(self.directory + "/counter", 'r+')
        line = counterFile.readline()
        counter = line.rstrip("\n")
        counterFile.close()
        return int(counter)

    # Encrypt And Decrypt

    def decrypt(self, ciphertext):
        """Load counter, increment, use it as a nonce decrypt data and store counter."""

        counter = self.loadCounter()
        counter += 1
        nonce = pack('LLL', 0, 0, counter)

        try:
            plaintext = self.box.decrypt(ciphertext, nonce)
        except CryptoError:
            # failed to decrypt
            return None

        port = unpack('H', plaintext)
        port = port[0]

        self.storeCounter(counter)

        return port


    def encrypt(self, plaintext, nonce):
        return self.box.encrypt(plaintext, nonce)

    # Serialization Methods

    def loadCipherKey(self):
        return self.loadKey(self.directory + "/cipher.key")

    def loadConfig(self):
        config = ConfigParser.SafeConfigParser()
        config.read(self.directory + "/config")
        
        return config.get('main', 'knock_port')

    def loadKey(self, keyFile):
        file = open(keyFile, 'r')
        key  = binascii.a2b_base64(file.readline())        

        file.close()
        return key

    def storeCipherKey(self):        
        self.storeKey(self.cipherKey, self.directory + "/cipher.key")

    def storeConfig(self):
        config = ConfigParser.SafeConfigParser()
        config.add_section('main')
        config.set('main', 'knock_port', str(self.knockPort))

        configFile = open(self.directory + "/config", 'w')
        config.write(configFile)
        configFile.close()

        self.setPermissions(self.directory + "/config")

    def storeKey(self, key, path):
        file = open(path, 'w')
        file.write(binascii.b2a_base64(key))
        file.close()

        self.setPermissions(path)

    # Permissions

    def setPermissions(self, path):
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    # Debug

    def printHex(self, val):
        for c in val:
            print "%#x" % ord(c),
            
        print ""
