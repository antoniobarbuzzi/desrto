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

from iptool import IPTool

class Flow:
    """This class can be used as a key in a dictionary to select a connection
    given a pair of peers. Two connections are considered the same if both
    peers are equal, despite the order in which they were passed to the
    class constructor.
    """

    def __init__(self, p1, p2):
        """This constructor takes two tuples, one for each peer. The first
        element in each tuple is the IP address as a string, and the
        second is the port as an integer.
        """
        assert(type(p1[0]) is int or type(p1[0]) is long) # 32/64 bit
        assert(type(p2[0]) is int or type(p2[0]) is long) # 32/64 bit
        assert(type(p1[1]) is int)
        assert(type(p2[1]) is int)
        self.p1 = p1
        self.p2 = p2

#    def getFilename(self):
        """Utility function that returns a filename composed by the IP
        addresses and ports of both peers.
        """
#        return '%s.%d-%s.%d.pcap'%(self.p1[0],self.p1[1],self.p2[0],self.p2[1])
    
    def __str__(self):
        #return "%s:%d <-> %s:%d" % ( socket.inet_ntop(socket.AF_INET, self.p1[0]), self.p1[1],socket.inet_ntop(socket.AF_INET, self.p2[0]), self.p2[1])  
        #return "%s:%d <-> %s:%d" % ( socket.inet_ntoa(struct.pack('!L',self.p1[0])), self.p1[1],socket.inet_ntoa(struct.pack('!L',self.p2[0])), self.p2[1])  
        return "%s:%d <-> %s:%d" % ( IPTool.num2ip(self.p1[0]), self.p1[1], IPTool.num2ip(self.p2[0]), self.p2[1])  
    def __repr__(self):
        return self.__str__()


    def __cmp__(self, other):
        if ((self.p1 == other.p1 and self.p2 == other.p2)
            or (self.p1 == other.p2 and self.p2 == other.p1)):
            return 0
        else:
            return -1

    def __hash__(self):
        return (hash(self.p1[0]) ^ hash(self.p1[1])
                ^ hash(self.p2[0]) ^ hash(self.p2[1]))



class NatFlowConnection():
    def __init__(self, flow_A, flow_B):
        self.flow_A = flow_A
        self.flow_B = flow_B
    
    def __str__(self):
        return "[%s] <=NAT=> [%s]" %(self.flow_A, self.flow_B)
        # scrivi verso del nat, e simili




if __name__ == "__main__":
    import iptool
    ip2num = iptool.IPTool.ip2num
    
    p1 = (ip2num("192.168.10.1"), 2)
    p2 = (ip2num("193.204.49.36"), 6)
    f1 = Flow(p1, p2)
    f2 = Flow(p2, p1)
    
    assert(f1==f2)
    d = {f1:"f1"}
    assert(d.has_key(f2))
    assert(d[f2]=="f1")
    
    print f1
    print f2
    
