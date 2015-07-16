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

from optparse import OptionParser
import os
from desrto import DeSRTO

BANNER = '''
DeSRTO

DeSRTO Copyright (C) 2009 Antonio Barbuzzi (antonio.barbuzzi@gmail.com)
Telematics Lab, DEE, Politecnico di Bari, Italy.

This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute
it under certain conditions. See COPYING for details.
'''

def main():
    global BANNER
    parser = OptionParser()
    parser.add_option("-s", "--data-sender-filename", dest="data_sender_filename",
                    help="Cap file of the Data Sender", metavar="FILE")

    parser.add_option("--data-sender-mac", dest="data_sender_mac",
                    help="Mac Address of the Data Sender Card. Mandatory if applicable", type="string", default=None)

    parser.add_option("-r", "--data-receiver-filename", dest="data_receiver_filename",
                    help="Cap file of the receiver", metavar="FILE")
    
    parser.add_option("--data-receiver-mac", dest="data_receiver_mac",
                    help="Mac Address of the Data Receiver Card. Mandatory if applicable", type="string", default=None)
    
    parser.add_option("--rto-list-filename", dest="rto_list_filename",
                    help="File with the list of RTO(s)", metavar="FILE")
    
    parser.add_option("-w", "--save-report", dest="report_filename",
                    help="Filename where to save a report", metavar="FILE")
    
#    parser.add_option("--nat", dest="nat", default=False,
#                    help="Flow is Natted")

    parser.add_option("--nat", 
                    action="store_true", dest="nat", default=False,
                    help="Flow is Natted")

    parser.add_option("--interprest-butterfly", 
                    action="store_true", dest="betabutterfly", default=False,
                    help="Enable the division of Butterfly RTO in Butterfly-NRTO and Butterfly-SRTO (beta)")

    parser.add_option("-q", "--quiet",
                    action="store_false", dest="verbose", default=True,
                    help="don't print status messages to stdout")

    (options, args) = parser.parse_args()
    
    if not options.data_sender_filename:
        parser.error("Data sender filename not defined")
    
    if not os.path.isfile(options.data_sender_filename):
        parser.error("Filename %s doesn't esist" % options.data_sender_filename)
    
    if not options.data_receiver_filename:
        parser.error("Data receiver filename not defined")
    
    if not os.path.isfile(options.data_receiver_filename):
        parser.error("Filename %s doesn't esist" % options.data_receiver_filename)
    
    #if not options.report_filename:
    #    options.report_filename = None
        

    if not options.rto_list_filename:
        a = options.data_receiver_filename
        path = "/".join(a.split('/')[:-1])
        if len(path)>0:
            options.rto_list_filename = path + "/rto_detected.log"
        else:
            options.rto_list_filename = "rto_detected.log"
    
    
    if not os.path.isfile(options.rto_list_filename):
        parser.error("Filename %s doesn't esist" % options.rto_list_filename)

    if options.verbose:
        print BANNER

    b = DeSRTO(sender_cap_file = options.data_sender_filename, receiver_cap_file = options.data_receiver_filename,
            sender_mac = options.data_sender_mac, receiver_mac=options.data_receiver_mac,
            rto_file = options.rto_list_filename, nat=options.nat, betabutterfly=options.betabutterfly)
    
    b.summary()
    b.analyse()
    if options.report_filename:
        b.dump_report(options.report_filename)

    
    
if __name__=='__main__':
    main()
