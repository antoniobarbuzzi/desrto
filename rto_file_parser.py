#!/usr/bin/env python
#-*- coding: utf-8 -*

#
# Copyright (c) 2009 Antonio Barbuzzi <antonio.barbuzzi@gmail.com>, 
# Telematics Lab, DEE, Politecnico di Bari, Italy. All rights reserved.
#
#
#    This file is part of DeSRTO.
#
#    DeSRTO is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    DeSRTO is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with DeSRTO.  If not, see <http://www.gnu.org/licenses/>.


#    For bug report and other information please visit Telematics Lab site
#    http://telematics.poliba.it or send an email to the author

import re

class RTO_List(object):
    def __init__(self, filename):
        self.f = open(filename)
        self.rto_number=0
        for line in self.f:
            self.rto_number +=1
        self.f.seek(0)
        #self.p = re.compile(r'^\w{3}\s[0-9]+\s[0-9:]+\s\w+\skernel:\s\[[. \d]+\]\sRTO_DETECTED\swcid\s*=\s*(?P<wcid>\d+)\s*-\s*Seq:(?P<seq>\d+)\stime:\((?P<sec>\d+),(?P<nsec>\d+)\)')
        self.p = re.compile(r'^\w{3}\s+[0-9]+\s[0-9:]+\s\w+\skernel:\s(\[[. \d]+\]\s)*RTO_DETECTED\swcid\s*=\s*(?P<wcid>[-\d]+)\s*-\s*Seq:(?P<seq>\d+)\stime:\((?P<nsec>\d+)')

    def __iter__(self):
        return self.next()

    def next(self):
        for line in self.f:
            m = self.p.search(line)
            if m:
                wcid, seq, nsec = (int(m.group(s)) for s in ["wcid", "seq", "nsec"])
                #print "RTO wcid: %d - seq: %d - sec: %d.%09d" %( wcid, seq, sec, nsec)
                yield (wcid, seq, nsec)
            else:
                print "Line non compliant %s" % line
        self.f.close()


if __name__ == "__main__":
    HOME="/home/antonio/Work/srto/BCN/2/downlink_20090215_190255/"
    RTO_NAME_A = HOME + "rto_detected.log"
    print "WCID SEQ NSEC"
    for wcid, seq, nsec in RTO_List(RTO_NAME_A):
        print wcid, seq, nsec
