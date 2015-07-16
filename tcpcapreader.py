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


import pcapy
import scapy.all as SCAPY
import struct

from iptool import IPTool
from flow import Flow

try:
    import progressbar
    import os
    import stat
    use_progressbar = True
except:
    use_progressbar = False


class FastTCPDecoder():
    def __init__(self, datalink, packet_string, my_mac):
        self.__packet_string = packet_string
        if datalink == pcapy.DLT_EN10MB:
            assert(my_mac) is not None
            self.my_mac = my_mac
            self.sent_by_us = True
            for i in xrange(6):
                #print "i = %d" % i
                b = self.__get_byte(6+i)
                if b != my_mac[i]:
                    self.sent_by_us = False
                    break
            N = 14
        elif datalink == pcapy.DLT_LINUX_SLL:
            sent_by_us = self.__get_word(0)
            if sent_by_us==4:
                self.sent_by_us=1
            elif sent_by_us==0:
                self.sent_by_us=0
            else:
                self.sent_by_us=-1
            N = 16
        else:
            raise "No decoder for datalink %s found" % datalink
        
        self.protocol = self.__get_word(N-2)
        self.is_tcp = False
        if self.protocol == 0x800:
            self.ip_protocol = self.__get_byte(N+9)
            if self.ip_protocol == 6:
                self.is_tcp = True
                self.ip_src = self.__get_long(N+12)
                self.ip_dst = self.__get_long(N+16)
                self.ip_id = self.__get_word(N+4)
                self.tcp_sport = self.__get_word(N+20+0)
                self.tcp_dport = self.__get_word(N+20+2)
                self.tcp_seq = self.__get_long(N+20+4)
                assert(self.ip_id<=65535 and self.ip_id>=0)
#maybe useless
                self.tcp_ack = self.__get_long(N+20+8)
                #self.tcp_flags = self.__get_byte(N+20+13) & 0x3F
                #self.ack = self.tcp_flags & 0x10
                #self.syn = self.tcp_flags & 0x2
                #self.tcp_data_length = self.__get_word(N+2) - 20 - ((self.__get_byte(N+20+12) & 0xf0)>>2)

    def __get_byte(self, index):
        bytes = self.__packet_string[index]
        (value,) = struct.unpack('!B', bytes)
        return value
    
    def __get_word(self, index):
        bytes = self.__packet_string[index:index+2]
        (value,) = struct.unpack('!H', bytes)
        return value
    
    def __get_long(self, index):
        bytes = self.__packet_string[index:index+4]
        (value,) = struct.unpack('!L', bytes)
        return value



class RawCapReader(object):
    def __init__(self, filename, cap_filter=r'ip proto \tcp'):
        self.filename = filename
        self.__cap_filter = cap_filter
        self.__pcapObj = pcapy.open_offline(self.filename)
        self.datalink = self.__pcapObj.datalink()

        if use_progressbar:
            self.filesize = os.stat(self.filename)[stat.ST_SIZE]
        self.read_len = 0

        if pcapy.DLT_EN10MB == self.datalink:
            #self.decoder = EthDecoder()
            self.decoder_str = "EthDecoder"
        elif pcapy.DLT_LINUX_SLL == self.datalink:
            #self.decoder = LinuxSLLDecoder()
            self.decoder_str = "LinuxSLLDecoder"
        else:
            raise Exception("Datalink type not supported: " % self.datalink)

        if self.__cap_filter:
            self.__pcapObj.setfilter(self.__cap_filter)

        print "Reading from %s: linktype=%s" % (filename, self.decoder_str)
        
        if use_progressbar:
            filetransfer = progressbar.FileTransferSpeed()
            filetransfer.units = ['B','KB','MB','GB','TB','PB']
#            widgets = ['Reading DUMP  ', progressbar.FileTransferSpeed(),' <<<', progressbar.Bar(), '>>> ', progressbar.Percentage(),' ', progressbar.ETA()]
            widgets = ['Reading DUMP  ', filetransfer,' <<<', progressbar.Bar(), '>>> ', progressbar.Percentage(),' ', progressbar.ETA()]
            self.pbar = progressbar.ProgressBar(widgets=widgets, maxval=self.filesize).start()
    
    def __iter__(self):
        return self
        
    def next(self):
        try:
            hdr, data = self.__pcapObj.next()
            if hdr is None: # Debian uses 02_remove_exception_on_next.patch, next() now returns None instead of raising an exception when pcap_next() returns NULL - from 0.10.6
                raise pcapy.PcapError()
            self.read_len+= len(data) + 16
            use_progressbar and self.pbar.update(self.read_len)
            return (hdr, data)
        except pcapy.PcapError:
            #print "READ TILL KNOW = ", self.read_len, " - FILESIZE =", self.filesize
            use_progressbar and self.pbar.finish()
            #print
            raise StopIteration





class TCPCapReader():
    def __init__(self, filename, my_mac=None, cap_filter=r'ip proto \tcp'):
        self.myreader = RawCapReader(filename, cap_filter) # inheritance is slower
        #self.my_ip = IPTool.ip2num(my_ip)
        self.flows_map={}
        self.pcap_array=[]
        self.packet_number=0

        if my_mac is not None:
            self.my_mac = [int(i, 16) for i in my_mac.split(":")]
        else:
            self.my_mac = None

        
        #bytes = struct.unpack('!H', hdr[0:2])
        #if bytes == 4:
        #my_ip = packet.myip

        for p in self.myreader:
            if p is not None:
                hdr, data = p
               # assert(len(data)>0)
                packet = FastTCPDecoder(self.myreader.datalink, data, my_mac=self.my_mac)

                if packet.is_tcp:
                    sec,  usec = hdr.getts()
                    p = packet
                    conn = Flow((p.ip_src, p.tcp_sport), (p.ip_dst, p.tcp_dport))
                    sent_packets, rcvd_packets, rcvd_acks = self.flows_map.get(conn, [{}, {}, {}])
                    #if p.ip_src == self.my_ip: #pacchetto inviato
                    if p.sent_by_us==1: #pacchetto inviato
                        self.pcap_array.append((sec, usec, 1, data))
                        self.packet_number+=1
                        tmp = sent_packets.get(p.tcp_seq, [None, {}])
                        if(tmp[0])==None:
                            tmp[0]=p.ip_id
                        tmp[1][p.ip_id]=self.packet_number-1
                        sent_packets[p.tcp_seq]=tmp
                    #elif p.ip_dst == self.my_ip: # paccketto ricevuto
                    elif p.sent_by_us==0: # paccketto ricevuto
                        self.pcap_array.append((sec, usec, 0, data))
                        self.packet_number+=1
                        tmp = rcvd_packets.get(p.tcp_seq, [None, {}])
                        if(tmp[0])==None:
                            tmp[0]=p.ip_id
                        tmp[1][p.ip_id]=self.packet_number-1
                        rcvd_packets[p.tcp_seq]=tmp
                        
                        tmp = rcvd_acks.get(p.tcp_ack, [None, {}])
                        if(tmp[0])==None:
                            tmp[0]=p.ip_id
                        tmp[1][p.ip_id]=self.packet_number-1
                        rcvd_acks[p.tcp_ack]=tmp
                    else:
                        print i, IPTool.num2ip(p.ip_src), IPTool.num2ip(p.ip_dst), p.tcp_sport, p.tcp_dport
                        assert(False)
                    self.flows_map[conn]=[sent_packets, rcvd_packets, rcvd_acks]
            else:
                print "None"
                assert(0)

    def summary(self):

        for flow in self.flows_map:
            sent_packets, rcvd_packets , rcvd_acks = self.flows_map[flow]
            if len(sent_packets)>0 and len(rcvd_packets)>0:
                print "%s <==> (sent seq = %d - rcvd seq = %d)"%(flow, len(sent_packets), len(rcvd_packets)), 
                if len(sent_packets)>len(rcvd_packets):
                    print " - sender capture file",
                else:
                    print " - receiver capture file",
                print " - %d packets!" % self.packet_number
            else:
                print "%s : not bidirectional flow" % flow
    
    
    def __does_packet_acks_sequence_number(self, packet, seq, consider_sack=False): ## ADD FLOW
        """ True se il pacchetto p è un acknowledgment di seq.
        In caso di sack, se l'ack number è minore di seq, ma il campo sack ackka seq.
        """
        if not packet.haslayer(SCAPY.TCP):
            return False

        t= packet["TCP"]
        if t.ack>seq:
            return True
        elif consider_sack:
            #untested, because unused
            for opt in t.options:
                if opt[0]=='SAck':
                    for start, end in opt[1:]:
                        if seq>=start and seq<end:
                            return True

        return False

    def __does_seqnumber_is_sent_in_scapypacket(self, seq, packet): ## ADD FLOW
        assert(packet.haslayer(SCAPY.TCP))
        t = packet["TCP"]
        if seq >= t.seq and seq <= (t.seq + len(t.payload)):
            return True
        else:
            return False
    
    def get_scapy_packet_in_flow(self, number, flow):
        '''Return packet in scapy format at index=number.
        packet has also the attributes p.is_sent, wich is true if the packets has been sent by self
        If the packet at the required index doesn't belong to the flow, None is returned.
        If number is higher than the highest packet number, IndexError is Raised.
        '''
        if(number>=self.packet_number):
            raise IndexError
        sec, usec, is_sent, data = self.pcap_array[number]
        raw_packet = FastTCPDecoder(self.myreader.datalink, data, my_mac=self.my_mac)
        flow2 = Flow((raw_packet.ip_src, raw_packet.tcp_sport), (raw_packet.ip_dst, raw_packet.tcp_dport))
        if flow2 == flow:
            LLcls = SCAPY.conf.l2types[self.myreader.datalink]
            p = LLcls(data)
            p.time = sec+0.000001*usec
            p.is_sent = is_sent
            return p
        else:
            return None
    
    def find_sent_seq(self, flow, seq, ip_id=None):
        ''' Trova id, position del pacchetto con sequence number,[id] specificato, usando un dict di sequence number
        '''
        sent_packets = self.flows_map[flow][0]
        s = sent_packets.get(seq, None)
        if s is None:
            return None
        if ip_id is None:
            ip_id = s[0]
        assert(ip_id<=65535 and ip_id>=0)
        position = s[1].get(ip_id, None)
        if position is None:
            return None
        return (ip_id, position)
    
    def find_sent_seq_repacked(self, flow, seq, from_index):
        ''' Trova ip, pacchetto della prima trasmissione of sequence_numer, a partire da from_index compreso.
        La ritrasmissione è trovata anche in presenza di ripacchettizzazione.
        Pertanto, se il sequence number da cercare è trovato al centro di un pacchetto, tale pacchetto viene restituito.
        '''
        while from_index<self.packet_number:
            p = self.get_scapy_packet_in_flow(number=from_index, flow=flow)
            from_index+=1
            if p is None:
                continue
            #print "repacked %d - Looking for %d seq=%d" % (from_index, seq, p["TCP"].seq)
            if self.__does_seqnumber_is_sent_in_scapypacket(seq=seq, packet=p):
                return (from_index-1, p)
        return None

    def find_rcvd_ack(self, flow, ack, ip_id):
        ''' Trova id, position del pacchetto con ack number,[id] specificato, usando un dict di ack number
        '''
        rcvd_acks = self.flows_map[flow][2]
        a = rcvd_acks.get(ack, None)
        if a is None:
            return None
        if ip_id is None:
            ip_id = a[0]
        assert(ip_id<=65535 and ip_id>=0)
        position = a[1].get(ip_id, None)
        if position is None:
            return None
        return (ip_id, position)


    def UNUSED_find_rcvd_ack(self, flow, ack, ip_id, from_index, to_time):
        """ Dato ack number e ip_id di un ack inviato, trova l'ack ricevuto a partire dall'indice from_index.
        Quando si interrompe???? dopo un max
        Potrebbe essere reimplementato usando un dict
        """
        assert(ip_id<=65535 and ip_id>=0)
        found_ack=False
        while True:
            try:
                p = self.get_scapy_packet_in_flow(from_index, flow)
            except IndexError:
                break

            from_index+=1

            if p is None:
                continue
            if not p.is_sent: #is rcvd
                if p["TCP"].ack == ack and p["IP"].id== ip_id:
                    print "found"
                    found_ack=True
                    break
            if p.time>to_time:
                break

        if found_ack:
            return None
        else:
            return (from_index-1, p)


    def UNUSED_find_ack_to_seq(self, flow, from_index, seq): # find_sent_ack_to_seq
        ''' Trova il primo pacchetto che acka un sequence number, a partire da una posizione nella lista dei pacchetti,
        La ricerca si interrompe nel momento in cui mi arriva la ritrasmissione di sequence_number_to_ack, in quanto tutti i pacchetti
        inviati da lì in poi possono accare la ritrasmissione.
        '''
        print "Find_ack_to_seq"
        index = from_index
        found_ack=False
        while True:
            print "get_scapy_packet_in_flow",
            p = self.get_scapy_packet_in_flow(index, flow)
            print "."
            index+=1
            if p is None:
                print "NONE"
                continue
            if p.is_sent:
                found_ack = self.__does_packet_acks_sequence_number(p, seq)
                if found_ack:
                    break
            else:
                print "received"

            if self.__does_seqnumber_is_sent_in_scapypacket(seq, p):
                break
        if not found_ack:
            return None
        else:
            return (index-1, p)


    def find_rcvd_seq(self, flow, seq, ip_id):
        ''' Trova id, position del pacchetto avente seq, id sul data_receiver, usando un dict di sequence_number
        '''
        rcvd_packets = self.flows_map[flow][1]
        s = rcvd_packets.get(seq, None)
        if s is None:
            return None
        if ip_id is None:
            ip_id = s[0]
        assert(ip_id<=65535 and ip_id>=0)
        position = s[1].get(ip_id, None)
        if position is None:
            return None
        #p = self.get_scapy_packet_in_flow(position, flow)
        return (ip_id, position)
    
    def find_all_sent_seqs(self, flow, tcp_seq):
        sent_packets = self.flows_map[flow][0]
        s = sent_packets.get(tcp_seq, None)
        if s is None:
            return None
        id_pktnumber = s[1].items()
        id_pktnumber.sort(key=lambda x:x[1]) # ordina rispetto a packet_number
        return id_pktnumber
    
    def find_sent_seq_before_t(self, flow, tcp_seq, t):
        id_pktnumber = self.find_all_sent_seqs(flow, tcp_seq)
        if id_pktnumber is not None:
            position = None
            min_deltat = None
            ip_id = None
            for i, n in id_pktnumber:
                packet = self.get_scapy_packet_in_flow(n, flow)
                till_t = t - packet.time
                if min_deltat is None or (till_t >=0 and till_t<min_deltat):
                    position = n
                    ip_id = i
                    min_deltat = till_t
                elif till_t<0:
                    break
            return (ip_id, position)
        else:
            return None
    
    #def find_all_sent_seqs_before_t(self, flow, tcp_seq, t, delta=0.1):
        #"""
        #delta serve x determinare il range massimo entro cui packet.time<t, ovvero packet.time-delta < time
        #"""
        #id_pktnumber = self.find_all_sent_seqs(flow, tcp_seq)
        #array=[]
        #for i, n in id_pktnumber:
            #sec, usec, is_sent, data = self.pcap_array[n]
            #_t = sec+0.000001*usec
            #if _t-delta >t:
                #break
            #array.append((i,n))
        #return array
        


    #def get_scapy_packet(self, number):
        ## mai chiamata
        #assert(False)
        #if(number>=self.packet_number):
            #return None
        #sec, usec, is_sent, data = self.pcap_array[number]
        #p = SCAPY.Raw(data)
        #p.time = sec+0.000001*usec
        #p.is_sent = is_sent
        #return p


    #def get_packet_in_flow(self, number, flow):
        #if(number>=self.packet_number):
            #return None
        #sec, usec, is_sent, data = self.pcap_array[number]
        #raw_packet = RawTCPDecoder(self.myreader.datalink, data)
        #raw_packet.time = sec + 0.000001*usec
        #flow2 = Flow((raw_packet.ip_src, raw_packet.tcp_sport), (raw_packet.ip_dst, raw_packet.tcp_dport))

        #if flow2 == flow:
            #return raw_packet
        #else:
            #return None






if __name__ == "__main__":
    import sys
    HOME="/home/antonio/Work/srto/BCN/2/downlink_20090215_190255/"
    DUMP_NAME_A = HOME + "eth_downlink_20090215_190255_reno.cap"
    filename = DUMP_NAME_A
    filename = len(sys.argv)==2 and sys.argv[1] or filename
    
    print filename
    #m = TCPCapReader(filename=filename, my_ip="84.88.62.77")
    m = TCPCapReader(filename=filename, my_mac='00:02:b3:e9:60:6e') #"84.88.62.77")
    m.summary()
