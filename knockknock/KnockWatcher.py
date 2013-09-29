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

# Internal modules
from LogEntry import LogEntry

# External modules
import syslog
import struct
import sys
import traceback


class KnockWatcher:

    def __init__(self, config, logFile, profiles, portOpener):
        self.config     = config
        self.logFile    = logFile
        self.profiles   = profiles
        self.portOpener = portOpener


    def tailAndProcess(self):
        for line in self.logFile.tail():
            logEntry = LogEntry(line)
            profile  = self.profiles.getProfileForPort(logEntry.getDestinationPort())
                
            if profile is not None:
                ciphertext = logEntry.getEncryptedData()
                sourceIP   = logEntry.getSourceIP()
                port       = profile.decrypt(ciphertext)
                if port is not None:
                    syslog.syslog("Received authenticated port-knock for port " + str(port) + " from " + sourceIP)
                    self.portOpener.open(sourceIP, port)
