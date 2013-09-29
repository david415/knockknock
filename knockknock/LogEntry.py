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

import string
from struct import *
import binascii
import syslog


class LogEntry:

    def __init__(self, line):
        self.buildTokenMap(line)

    def buildTokenMap(self, line):
        self.tokenMap = dict()

        for token in line.split():
            index = token.find("=");            
            if index != -1:
                exploded = token.split('=')
                self.tokenMap[exploded[0]] = exploded[1]

        if 'OPT' in line:
            opt = line.split('OPT ')[1]
            if opt.startswith('('):
                opt = opt[1:-1] # remove parenthesis
                opt = opt[4:16] # grab 12 chars
                opt = binascii.unhexlify(opt)
                self.tokenMap['OPT'] = opt

    def getDestinationPort(self):
        if self.tokenMap.has_key('DPT'):
            return int(self.tokenMap['DPT'])
        else:
            return None

    def getEncryptedData(self):
        expected_tokens = set(['ID', 'SEQ', 'ACK', 'WINDOW','OPT'])

        if len(expected_tokens - set(self.tokenMap.keys())) != 0:
            syslog.syslog("did not find all expected TCP header fields: %s" % self.tokenMap.keys())
            return None

        ciphertext = pack('!HIIH', int(self.tokenMap['ID']), int(self.tokenMap['SEQ']), int(self.tokenMap['ACK']), int(self.tokenMap['WINDOW'])) + self.tokenMap['OPT']
        return ciphertext

    def getSourceIP(self):
        return self.tokenMap['SRC']
