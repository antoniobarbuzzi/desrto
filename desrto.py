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



import sys
from tcpcapreader import TCPCapReader
from flow import Flow,NatFlowConnection
from rto_file_parser import RTO_List
import scapy
from iptool import IPTool

DEBUG=True


class DeSRTO:
    def __init__(self, sender_cap_file, receiver_cap_file, rto_file, sender_ip=None, receiver_ip=None, sender_mac = None, receiver_mac = None, sender_port=None, receiver_port=None, nat=False, betabutterfly=True):
        self.sender_cap_file = sender_cap_file
        self.receiver_cap_file = receiver_cap_file
        self.rto_file = rto_file
        self.sender_mac = sender_mac
        self.receiver_mac = receiver_mac
        self.rto_list = RTO_List(self.rto_file)
        self.nat = nat
        self.betabutterfly = betabutterfly
        if self.rto_list.rto_number==0:
            return
        self.data_sender = TCPCapReader(filename = self.sender_cap_file, my_mac=self.sender_mac)
        self.data_sender.summary()
        self.ack_sender = TCPCapReader(filename = self.receiver_cap_file, my_mac=self.receiver_mac)
        self.ack_sender.summary()

        print "self.nat = %s" % self.nat
        
        
        if sender_ip and sender_port and receiver_ip and receiver_port:
            assert(False)
            self.sender_ip = sender_ip
            self.receiver_ip = receiver_ip
            self.sender_port = sender_port
            self.receiver_port = receiver_port        
            ip1 = IPTool.ip2num(self.sender_ip)
            ip2 = IPTool.ip2num(self.receiver_ip)
            self.flow = Flow((ip1, self.sender_port), (ip2, self.receiver_port))
        else:
#            f1 = set(self.data_sender.flows_map.keys())
#            f2 = set(self.ack_sender.flows_map.keys())
            f1 = set([f for f, (s, r, a) in self.data_sender.flows_map.iteritems() if (len(s)>0 and len(r)>0)]) #solo flussi bidirezionali
            f2 = set([f for f, (s, r, a) in self.ack_sender.flows_map.iteritems() if (len(s)>0 and len(r)>0)]) 
            bidirectional_flows = f1.intersection(f2)

            if len(bidirectional_flows)>1:
                print "Too many flows between two peers, we should choose one. Not implemented yet."
                assert(False)
            elif len(bidirectional_flows)==0:
                if not self.nat:
                    print "No bidirectional flows (maybe there is nat, use --nat option)"
                    assert(False)
                elif self.nat and len(f1)==1 and len(f2)==1:
                    f1 = list(f1)[0]
                    f2 = list(f2)[0]
                    self.nat_connection = NatFlowConnection(f1, f2)
                    print "Nat Enabled:", self.nat_connection
                elif self.nat and (len(f1)>1 or len(f2)>1):
                    print "Too many flows... You have to choose one manually. Not IMPLEMENTED"
                    print f1, f2
                    assert(0)
                    print "Chosen Flow:", self.flow
                else:
                    print "Unforeseen Event!"
                    assert(0)
            elif len(bidirectional_flows)==1 and not self.nat:
                self.flow=list(bidirectional_flows)[0]
            else:
                print "Unforeseen Event!"
                assert(0)


    def summary(self):
        print "_"*80
        print "Sender CAP File = %s" % self.sender_cap_file
        print "Receiver CAP File = %s" % self.receiver_cap_file
        print "RTO List = %s" % self.rto_file
        if self.rto_list.rto_number==0:
            print "No RTO"
        elif not self.nat:
            print "Searching RTO for flow %s" % self.flow
        else:
            print "Searching RTO for flow %s" % self.nat_connection
        print "_"*80
        print


    def analyse(self, output_filename="tmp_rto_srto.txt"):
        self.report = []
        self.errors = 0
        if self.rto_list.rto_number==0:
            return
        data_sender = self.data_sender
        ack_sender = self.ack_sender
        
        if not self.nat:
            sender_flow = self.flow
            receiver_flow = self.flow
        else:
            sender_flow = self.nat_connection.flow_A
            receiver_flow = self.nat_connection.flow_B

        MAX_TIME_TO_LOOK_FOR_ACK=20
        print "Examining %d RTO(s)" % self.rto_list.rto_number

        for wcid, seq, nsec in self.rto_list:
            print "=" * 20, wcid, seq, nsec, "="*20
            sys.stdout.flush()
            rto_time = nsec/1000000000.
            is_nrto=True
            strange_case = False
            
            print "Looking for segment (seq: %d, t = %0.3f s) on sender" % (seq, rto_time)
            uno = data_sender.find_sent_seq_before_t(sender_flow, seq, rto_time) #ip_id, position = uno
            if uno is None:
                print "Cannot find rto segments... maybe it was dropped by the kernel. All the results from this files could be wrong"
                self.errors+=1
                continue


            assert(uno is not None)
            print "Looking for segment (seq=%d - ip.id = %d) on the receiver" %(seq, uno[0])
            due = ack_sender.find_rcvd_seq(receiver_flow, seq, uno[0])
            #ip_id, position = due
            if due:
                #trovo tempo di arrivo del pacchetto ritrasmesso
                #print "trovo tempo di arrivo del pacchetto ritrasmesso"
                print "Looking for the retransmission on the sender (seq=%d - index=%d)" %(seq, uno[1]+1)
                retrasmitted_pkt = data_sender.find_sent_seq_repacked(flow=sender_flow, seq=seq, from_index = uno[1]+1) #position, packet
                if retrasmitted_pkt is None:
                    print "It seems that traces aren't complete..." #se è un rto, allora ci sarà sicuramente una ritrasmissione
                    self.errors+=1
                    break
                assert(retrasmitted_pkt is not None)
                assert(retrasmitted_pkt[0] != uno[1])
                
                # mi serve il primo pacchetto ritrasmesso che arriva a destinazione
                while True:
                    print "Looking for the retransmission on the receiver (seq=%d, id=%d)" %(retrasmitted_pkt[1]["TCP"].seq, retrasmitted_pkt[1]["IP"].id)
                    rcvd_retrasmission = ack_sender.find_rcvd_seq(flow=receiver_flow, seq=retrasmitted_pkt[1]["TCP"].seq, ip_id=retrasmitted_pkt[1]["IP"].id)  # (ip_id, position)
                    while rcvd_retrasmission is None:
                        print "Retransmission Lost. Looking for first retransmitted packet"
                        nn = retrasmitted_pkt[0]+1
                        retrasmitted_pkt = (nn, data_sender.get_scapy_packet_in_flow(flow=sender_flow, number=nn) )
                        if not retrasmitted_pkt[1].is_sent:
                            continue
                        print "Looking for retransmitted packet on the receiver (seq:%d - ip.id=%d)" % (retrasmitted_pkt[1]["TCP"].seq, retrasmitted_pkt[1]["IP"].id)
                        rcvd_retrasmission = ack_sender.find_rcvd_seq(flow=receiver_flow, seq=retrasmitted_pkt[1]["TCP"].seq, ip_id=retrasmitted_pkt[1]["IP"].id)  # (ip_id, position)
                    time_rcvd_retransmission = ack_sender.get_scapy_packet_in_flow(flow=receiver_flow, number=rcvd_retrasmission[1]).time
                    if rcvd_retrasmission is not None:
                        break
                print "Looking for sent segments on the sender, from index %d (first rto segmnet) to t<%.3f (time of send of last successufull retrasmission)" %(uno[1], retrasmitted_pkt[1].time)
                
                sent_packets_in_window = [] # comprensivi del primo
                i = uno[1] # position
                while True:
                    packet = data_sender.get_scapy_packet_in_flow(flow=sender_flow, number=i)
                    i+=1
                    if packet is None or not packet.is_sent:
                        continue
                    elif packet.time<retrasmitted_pkt[1].time: #changed to < from <=
                        sent_packets_in_window.append(packet)
                    else:
                        break

                #assert(retrasmitted_pkt not in sent_packets_in_window) ///MMMMMMMMM, mi sa che è il contrario
                #assert(retrasmitted_pkt in sent_packets_in_window) #OK

                #trovo i corrispondenti pacchetti ricevuti in una finestra
                print "Looking for the corresponding received segments ",
                sys.stdout.flush()
                #print "trovo i corrispondenti pacchetti ricevuti in una finestra"
                rcvd_window_pkts = []

                for pkt in sent_packets_in_window:
                    id_ = pkt["IP"].id
                    seq_ = pkt["TCP"].seq
                    rcvd_pkt = ack_sender.find_rcvd_seq(receiver_flow, seq_, id_) # (ip_id, position)
                    if rcvd_pkt is not None:
                        rcvd_window_pkts.append(rcvd_pkt)
                        print ".",
                    sys.stdout.flush()

                assert(len(rcvd_window_pkts)>0)
                t_rcvd_windows_pkts = [(ack_sender.get_scapy_packet_in_flow(flow=receiver_flow, number=position)).time for ip_id, position in rcvd_window_pkts]
                assert(len(t_rcvd_windows_pkts)>0)
                
                if time_rcvd_retransmission < max(t_rcvd_windows_pkts):
                    print "Reordering, let's hope to not have strange cases"
                
                positions_rcvd_pkts = [position for ip_id, position in rcvd_window_pkts]
                
                uno_packet = data_sender.get_scapy_packet_in_flow(flow=sender_flow, number=uno[1])
                
                ack_to_find = uno_packet["TCP"].seq + len(uno_packet["TCP"].payload)+1
                #if uno_packet["TCP"].flags
                

                print "Looking for sent acks [acks=%d] from the receiver till the first packet after the retransmitted ones" % ack_to_find
                ack_to_finds = []
                ack_to_finds_timestamp={}
                for i in range(min(positions_rcvd_pkts), max(positions_rcvd_pkts)+2):###################### first packet after max
                    pkt = ack_sender.get_scapy_packet_in_flow(flow=receiver_flow, number=i)
                    #if pkt is None or pkt.is_sent is False:
                    if pkt is None or pkt.is_sent is True:
                        continue
                    if pkt["TCP"].ack>=ack_to_find:
                        code = (pkt["IP"].id, pkt["TCP"].ack)
                        ack_to_finds.append(code)
                        ack_to_finds_timestamp[code]=pkt.time

                print "Looking for received acks on the sender"
                assert(len(ack_to_finds)>0)

                for code in ack_to_finds:
                    ip_id, ack = code
                    tmp = data_sender.find_rcvd_ack(flow=sender_flow, ack=ack, ip_id=ip_id)
                    if tmp is None:
                        continue
                    pkt = data_sender.get_scapy_packet_in_flow(flow=sender_flow, number=tmp[1])
                    assert(pkt is not None)
                    assert(not pkt.is_sent)
                    is_nrto = False
                    if ack_to_finds_timestamp[code] > time_rcvd_retransmission:
                        print "Ack received was sent after the receipt of the retransmission"
                        strange_case = True
                    break

                if is_nrto and max(ack_to_finds_timestamp.values()) > time_rcvd_retransmission:
                    strange_case = True
            else:
                print "Packet lost"


            rto_type_code = 0
            if not is_nrto:
                rto_type_code |= 0x1
            if strange_case:
                rto_type_code |= 0x10

            if not strange_case:
                if is_nrto:
                    print "NRTO"
                    rto_type = "NRTO"
                else:
                    print "SRTO"
                    rto_type = "SRTO"
            elif self.betabutterfly is True:
                print "Butterfly"
                if is_nrto:
                    print "NRTO"
                    rto_type = "ButterflyNRTO"
                else:
                    print "SRTO"
                    rto_type = "ButterflySRTO"
            else:
                print "Butterfly"
                rto_type = "ButterflyRTO"
            
            self.report.append((wcid, seq, nsec, rto_type, rto_type_code))
    
    
    def dump_report(self, filename=None):
        saveout = sys.stdout
        srto_number = 0
        butterfly_number = 0
        if filename is not None:
            fout = open(filename, 'a')
            sys.stdout = fout
        if self.errors > 0:
            print "Traces are damaged"
        else:
            for wcid, seq, nsec, rto_type, rto_type_code in self.report:
                print wcid, seq, nsec, rto_type
                if (rto_type_code & 0x1):
                    srto_number+=1
                if (rto_type_code & 0x10):
                    butterfly_number+=1
        
        self.summary()
        print "RTO examined = %d" % len(self.report)
        print "SRTO = %d" % srto_number
        print "Butterfly = %d" % butterfly_number
        print "-"*72
        
        sys.stdout = saveout
        if filename is not None:
            fout.close()


def main():
    '''
    host A trasmette ad host B
    A inizia la comunicazione
    semplificando, B trasmette gli ack
    controllo gli srto su A
    '''

    HOME="/home/antonio/Work/srto/BCN/2/downlink_20090215_190255/"
    DUMP_NAME_A = HOME + "eth_downlink_20090215_190255_reno.cap"
    DUMP_NAME_B = HOME + "ppp0_downlink_20090215_190255_reno.cap"
    RTO_NAME_A = HOME + "rto_detected.log"
    SRC = "84.88.62.77"
    DSTPORT=5001

    #b = DeSRTO(DUMP_NAME_A, DUMP_NAME_B, RTO_NAME_A, "84.88.62.77", "62.32.236.157", 52626, DSTPORT)
    #b = DeSRTO(DUMP_NAME_A, DUMP_NAME_B, RTO_NAME_A, "84.88.62.77", "62.32.236.157")
    b = DeSRTO(DUMP_NAME_A, DUMP_NAME_B, RTO_NAME_A, sender_mac="00:02:b3:e9:60:6e")
    
    b.summary()
    b.analyse()
    

if __name__== "__main__":
    main()
