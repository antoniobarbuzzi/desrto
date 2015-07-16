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

import socket, struct
__version__="0.2"


class IPTool:

    def dec2bin(dec):
        count = 1
        bin = ''
        while dec:
            bin = (dec % 2 and '1' or '0') + bin
            dec = long(dec/2)
            if not count%8:
                bin ="." + bin
            count+=1
        if bin and bin[0]==".":
            bin=bin[1:]
        return bin or '0'
    dec2bin = staticmethod(dec2bin)

    def ip2num(ip):
        "convert decimal dotted quad string to long integer"
        #return struct.unpack('>L',socket.inet_aton(ip))[0]
        return struct.unpack('>L',socket.inet_pton(socket.AF_INET, ip))[0]
    ip2num = staticmethod(ip2num)

    def num2ip(n):
        "convert long int to dotted quad string"
        a=struct.pack('>L',n)
#        return socket.inet_ntoa(a)
        return socket.inet_ntop(socket.AF_INET, a)
    num2ip = staticmethod(num2ip)

    def smallestNetwork(ip_list):
        """ Vuole una list di ip come stringhe
        """
        ###############################
        addlist = [IPTool.ip2num(x) for x in ip_list]
        addlist.sort()
        mask = IPTool.ip2num('255.255.255.255')
        net = addlist[0]
        for add in addlist[1:]:
            mask = net ^ ~add
            net = net & mask
        mask = mask & 0xffffffff # convert in unsigned
        net = net & 0xffffffff # convert in unsigned
        #
        # Now set all bits to the right of
        # the leftmost zero to zero for the correct
        # netmask, and use the mask to derive the
        # correct network number.
        #
        zeros = 0
        cid=0
        for bit in range(32, 0, -1):
            pos = bit -1
            zeros = zeros | (~mask & (1<< pos))
            if zeros:
                mask = mask & ~(1 << pos)
            else:
                cid+=1
        

        net = net & mask
        
        #print "Mask:   ", IPTool.num2ip(mask)
        #print "Network:", IPTool.num2ip(net)
        #print "CIDR_NET: %s/%d" %(IPTool.num2ip(net), cid)

        return ("%s/%d" % (IPTool.num2ip(net), cid), IPTool.num2ip(net),  IPTool.num2ip(mask))

    smallestNetwork = staticmethod(smallestNetwork)



    def __smallestNetwork(ip_list):
        """ Vuole una list di ip come stringhe
	    Vecchia versione inutilizzata

        """
        ###############################
        addlist = [IPTool.ip2num(x) for x in ip_list]
        addlist.sort()
        mask = IPTool.ip2num('255.255.255.255')
        net = addlist[0]
        for add in addlist[1:]:
            mask = net ^ ~add
            net = net & mask

        #
        # Now set all bits to the right of
        # the leftmost zero to zero for the correct
        # netmask, and use the mask to derive the
        # correct network number.
        #
        zeros = 0
        cid=0
        for bit in range(32, 0, -1):
            pos = bit -1
            zeros = zeros | (~mask & (1<< pos))
            if zeros:
                mask = mask & ~(1 << pos)
            else:
                cid+=1

        net = net & mask
        print "Mask:   ", IPTool.num2ip(mask)
        print "Network:", IPTool.num2ip(net)
        print "CIDR_NET: %s/%d" %(IPTool.num2ip(net), cid)

        return ("%s/%d" % (IPTool.num2ip(net), cid), IPTool.num2ip(net),  IPTool.num2ip(mask))

    __smallestNetwork = staticmethod(__smallestNetwork)

    def smallest_ip(net):
        net_str, m = net.split("/")
        m = int(m)
        mask = (pow(2,m)-1)<<32-m
        numeric_net  = IPTool.ip2num(net_str)
        return IPTool.num2ip(numeric_net & mask)
    smallest_ip = staticmethod(smallest_ip)

    def biggest_ip(net):
        net_str, m = net.split("/")
        m = int(m)
        mask = (pow(2,m)-1)<<32-m
        numeric_net  = IPTool.ip2num(net_str)
        maxip = numeric_net | ( mask ^ 0xffffffff)
        return IPTool.num2ip(maxip)
    biggest_ip = staticmethod(biggest_ip)

    def ip_in_net(ip, net):
        net_str, m = net.split("/")
        m = int(m)
        mask = (pow(2,m)-1)<<32-m
        numeric_net  = IPTool.ip2num(net_str)
        minip = numeric_net & mask
        maxip = numeric_net | ( mask ^ 0xffffffff)

        numeric_ip = IPTool.ip2num(ip)
        return numeric_ip>=minip and numeric_ip<=maxip
    ip_in_net = staticmethod(ip_in_net)

class CIDR_Net:
    def __init__(self, net):
        self.net=net
        net_string, m = net.split("/")
        m = int(m)
        self.mask = (pow(2,m)-1)<<32-m
        self.numeric_net  = IPTool.ip2num(net_string)
        self.minip = self.numeric_net & self.mask
        self.maxip = self.numeric_net | ( self.mask ^ 0xffffffff)

    def __repr__(self):
        return "<" + self.net + ">"

    def __str__(self):
        return self.__repr__()

    def hasIP(self,ip):
        tmp = IPTool.ip2num(ip)
        return tmp>=self.minip and tmp<=self.maxip


if __name__ == "__main__":
    try:
        import progressbar
        pbar_available = True
    except:
        pbar_available = False
    import random
    
    print "Testing CIDR_Net - IPTool.num2ip"
    a = CIDR_Net(net="193.204.49.36/24")
    print "\ttesting CIDR_Net.minip - CIDR_Net.maxip",
    
    if pbar_available:
        widgets = ['Testing num2ip/ip2num ', progressbar.FileTransferSpeed(),' <<<', progressbar.Bar(), '>>> ', progressbar.Percentage(),' ', progressbar.ETA()]
        pbar = progressbar.ProgressBar(widgets=widgets, maxval=4294967295).start()
    INCREMENT = 1000
    for n in xrange(0, 4294967296, INCREMENT):
        k = random.randrange(0,INCREMENT) + n
        if not IPTool.ip2num(IPTool.num2ip(k))==k:
            print k
            assert (IPTool.ip2num(IPTool.num2ip(k))==k)
        pbar_available and pbar.update(n)
    pbar_available and pbar.finish()

    assert IPTool.num2ip(a.minip) == "193.204.49.0"
    assert IPTool.num2ip(a.maxip) == "193.204.49.255"
    a = CIDR_Net(net="193.204.49.36/16")
    assert IPTool.num2ip(a.minip) == "193.204.0.0"
    assert IPTool.num2ip(a.maxip) == "193.204.255.255"
    a = CIDR_Net(net="193.204.49.36/32")
    assert IPTool.num2ip(a.minip) == "193.204.49.36"
    assert IPTool.num2ip(a.maxip) == "193.204.49.36"
    a = CIDR_Net(net="193.204.49.36/8")
    assert IPTool.num2ip(a.minip) == "193.0.0.0"
    assert IPTool.num2ip(a.maxip) == "193.255.255.255"
    a = CIDR_Net(net="193.204.49.36/0")
    assert IPTool.num2ip(a.minip) == "0.0.0.0"
    assert IPTool.num2ip(a.maxip) == "255.255.255.255"
    a = CIDR_Net(net="193.204.49.36/30")
    assert IPTool.num2ip(a.minip) == "193.204.49.36"
    assert IPTool.num2ip(a.maxip) == "193.204.49.39"
    print "OK"
    print "\ttesting CIDR_Net.hasIP",
    assert a.hasIP("193.204.49.27") is False
    assert a.hasIP("193.204.49.37") is True
    assert a.hasIP("193.204.49.39") is True
    assert a.hasIP("193.204.49.36") is True
    print "OK"
    print "OK"

    print "Testing IPTool.smallestNetwork... ",
    ip_list = ['192.168.10.23', '192.168.10.15', '192.168.14.15', '192.168.12.25']
    cnet, net, mask = IPTool.smallestNetwork(ip_list)
    cn = CIDR_Net(cnet)
    for ip in ip_list:
        assert cn.hasIP(ip)
#Address:   193.204.49.1         11000001.11001100.00110001.00000001
#Address:   193.204.49.236       11000001.11001100.00110001.11101100
#net:                            11000001.11001100.00110001.00000000
#mask                            11111111.11111111.11111111.00000000
#           193.204.49.0/24


    ip_list = ['193.204.49.76', '193.204.49.74', '193.204.49.1', '193.204.49.60', '193.204.49.70', '193.204.49.71', '193.204.49.36', '193.204.49.205', '193.204.49.236', '193.204.49.20', '193.204.49.30', '193.204.49.50', '193.204.49.24']
    cnet, net, mask = IPTool.smallestNetwork(ip_list)
    cn = CIDR_Net(cnet)
    for ip in ip_list:
        assert cn.hasIP(ip)
    print "OK"

    print "Testing IPTool.smallest_ip and IPTool.biggest_ip...",
    assert IPTool.smallest_ip("192.168.99.0/24")=="192.168.99.0"
    assert IPTool.smallest_ip("192.168.99.128/25")=="192.168.99.128"
    assert IPTool.biggest_ip("192.168.99.128/24")=="192.168.99.255"
    assert IPTool.biggest_ip("192.168.99.0/25")=="192.168.99.127"
    print "OK"

    print "Testing IPTool.ip_in_net...",
    assert IPTool.ip_in_net("192.168.99.200", "192.168.99.0/24")==True
    assert IPTool.ip_in_net("192.168.99.200", "192.168.99.0/25")==False
    print "OK"

    print "Testing IPTool.dec2bin...",
    assert IPTool.dec2bin(IPTool.ip2num("255.255.255.255"))=="11111111.11111111.11111111.11111111"
    assert IPTool.dec2bin(IPTool.ip2num("255.255.255.0"))=="11111111.11111111.11111111.00000000"
    print "OK"
