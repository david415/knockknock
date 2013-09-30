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

# External modules
import syslog
import struct
import sys
import traceback
from nflog_cffi import NFLOG
from scapy.all import *


class KnockWatcher:

    def __init__(self, config, profiles, portOpener):
        self.config     = config
        self.profiles   = profiles
        self.portOpener = portOpener

        qids            = 0, 1
        self.nflog      = NFLOG().generator(qids)

    def process_nflog_packets(self):
        next(self.nflog)
        for pkt in self.nflog:
            if pkt is None:
                continue
            if TCP not in IP(pkt):
                continue

            profile  = self.profiles.getProfileForPort(IP(pkt)[TCP].dport)
            if profile is None:
                continue
            ciphertext = self.get_ciphertext_from_packet(pkt)
            port       = profile.decrypt(ciphertext)
            
            if port is not None:
                sourceIP = IP(pkt).src
                syslog.syslog("Received authenticated port-knock for port " + str(port) + " from " + sourceIP)
                self.portOpener.open(sourceIP, port)


    def get_ciphertext_from_packet(self, pkt):
        pkt = IP(pkt)
        opt = dict(pkt[TCP].options)['MSS']
        return struct.pack('!HIIH', 
             pkt.id,
             pkt[TCP].seq,
             pkt[TCP].ack,
             pkt[TCP].window) + opt
