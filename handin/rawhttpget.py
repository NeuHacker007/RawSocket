#!/usr/bin/env python

'''
Projetcts: Raw Socket
Purpose: downloads associated file. 
Project runs like: ./rawhttpget [URL]
Author: @Yifan Zhang (zhang.yifan2@husky.neu.edu) 001616011
'''
'''
 1. URL process
         if (with complete file name)
                 createFile(name is the same above)
         else 
                 createFile( name is Index.html)
2. HTTP process
          if (status == 200)
               continue
          else 
              print ('error')
              exit(0)
3. ceate two Sockets  
               recieve socket 
                   - socket.socket(AF_INTEL, SOCK_STREAM, IPPROTO_IP)
               send socket
                   - socket.socket(AF_INTEL, SOCK_STREAM, IPPROTO_RAW)
                   
?
 - process login
'''
'''
Methods:
URLprocess()
sendsocket()
recievesocket()
responseSplit()
checksum() 
IPHeadercomposite
TCPHeadercomposite
IPFragmentation()
IsLastIPFragment()
getCurrentNetworkMTU()

createfile():
        if (url with file extension)
              create file ( the same name and extension with the file)
              write down HTML body from response into file
        else 
               create file (with the name and extension by default index.html)
               writedown HTML body from response into file
        
packetsFilter() : only process  packets related to our program
         if (packet is TCP)
                if (source IP match && destnation IP match)
                      keep this packet 
         else 
            break
incomingPacketsSorting(): recomposite the packets according to the sequence info
            read Packets sequence
            sort with  sequence 
            concatenate the data
PacketsDropDetection() : if response ACKS dosn't increase, packet is dropped retransmitting. 
IsACKRecive(): 
DuplicateAcksDetection()
Timeout()): if over 1min not acked, the packect should be marked as dropped
CongestionWindowAdjustment(): 
             congestionWindow = 1
             if (no drop)
                   congestionWindow += 50
             else 
                    congestionWindow = 1 
            if (congestionWindow > 1000)
                congetionWindow = 1000
            return congestionWindow
HTTPGETHeader()
extractStatusCode()
isStatus200()
'''
import socket
import sys
import urlparse
import io
import re
import fcntl
import binascii
import random
from struct import *
import Queue
import time

TIME_OUT = 180
ACK_TIME_OUT = 60
class HTTP:
    CRLF = "\r\n\r\n"
    def __init__(self):
        pass
    @staticmethod
    def GETRequest(_url):
        urlStr = urlparse.urlparse(_url)
        host = urlStr.netloc
        if not host:
            host = _url
        if not _url:
            path = "/"
        path = urlStr.path 
        if host == _url:
            path = "/"
        getHeader = [
                "GET %s HTTP/1.1\r\n" %path,
                "Host: %s\r\n" % host,
                "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:44.0) Gecko/20100101 Firefox/44.0\r\n",
                "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                "Accept-Language: en-US,en;q=0.5\r\n",
                "Referer: %s\r\n"%_url,
                "Connection: keep-alive",          
        ]  
        return "".join(getHeader) + HTTP.CRLF
    
    @staticmethod
    def responseSplit(_response):
        httpHeader,delimiter,body = _response.partition(HTTP.CRLF)
        return (httpHeader, body) 
    
    @staticmethod
    def extractStatusCode(_responseHeader):
        if not _responseHeader:
            print "Response Header is empty"
            exit(0)
        tagLines = _responseHeader.split('\n')
        statusCode = tagLines[0].split(' ')[2]
        return statusCode
    
    @staticmethod
    def isStatus200(_responseHeader):
        statusCode = HTTP.extractStatusCode(_responseHeader)
        if statusCode.startswith('2'):
            return True
        return False
    @staticmethod
    def isResponseChunked( responseHeader):
        if "Transfer-Encoding: chunked" in responseHeader:
            return True
        return False
    @staticmethod
    def isContentLength( _header):
        if ("Content-Length:" in _header):
            return True
        return False
    @staticmethod
    def getContentLength(_header):
        lengthPatternStr = "Content-Length: (.*?)\r\n"
        lengthPattern = re.compile(lengthPatternStr)
        length = re.findall(lengthPattern, _header)
        
        if len(length) == 0:
            return 0
        return int(length[0]) 
        
class customerSocket:
    def __init__(self):
        pass
    @staticmethod
    def senderSocket():
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,socket.IPPROTO_RAW)
        return sock
    @staticmethod
    def recieveSocket():
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_IP)
        return sock 
    @staticmethod
    def normalSocket():
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        return sock
    @staticmethod
    def rawRecvSock():
        sock = socket.socket(socket.AF_INET,socket.SOCK_RAW, socket.IPPROTO_TCP)
        return sock
    @staticmethod
    def udpSock():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return sock
    @staticmethod
    def recieve( tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock):
        responseBody = ' '
        response =  baseUtility.recv(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock,responseBody)
        header, body = HTTP.responseSplit(response)
        responseBody += response
        #if HTTP.isResponseChunked(header):
            #if "\r\n0\r\n" in body:
                #return responseBody
            #while True:
                #tmpResponse = str( baseUtility.recv(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock, responseBody))
                #if (tmpResponse[0] == "0"):
                    #break
                #elif ("\n0\r\n" in tmpResponse):
                    #responseBody += tmpResponse
                    #break
                #else:
                    #responseBody += tmpResponse
            #return responseBody
        #elif  HTTP.isContentLength(header):
            #data_pos = responseBody.find(HTTP.CRLF)+ 4
            #data_recv_len = len(responseBody[data_pos:])
            #content_len = HTTP.getContentLength(header)
            
            #required_data_len = content_len - data_recv_len
            
            #if required_data_len == 0:
                #return responseBody
            #while required_data_len != 0:
                #tmp =  baseUtility.recv(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock,responseBody)
                #responseBody += tmp 
                #required_data_len -= len(tmp)
        return responseBody
        #else: 
            #return ""

class IP:
    source_IP = ""
    dest_IP = ""
    ip_version = 4
    ip_internet_header_length = 5 # indicates that the data is begin after 5 32-bits words aka rows. the minimum length is 5
    ip_typeOfService = 0 
    ip_total_len = 0  #
    ip_flag = 2
    ip_identification = 666 # 16 bit indentifying value assigned by sender to aid in assembling the framents of  a data gram 
    ip_frag_offset = 0 # this field indicates where in the datagram this fragment belongs
    ip_TTL = 64 # 8 -bit maximum time the datagram is allowed to remain in the internet system
    ip_protocol = socket.IPPROTO_TCP
    ip_checksum = 0 # 16-bit  checksum on header only
      
    def __init__(self, sourceIP, destIP):
        self.source_IP = sourceIP
        self.dest_IP = destIP
    def getIPheader(self):
        ip_ver_IHL = (self.ip_version << 4) + self.ip_internet_header_length
        ip_source_IP = socket.inet_aton(self.source_IP)
        ip_dest_IP = socket.inet_aton(self.dest_IP)
        ip_flag_fragment = (self.ip_flag << 13) + self.ip_frag_offset
        ip_header = pack('!BBHHHBBH4s4s', ip_ver_IHL, self.ip_typeOfService, self.ip_total_len, self.ip_identification, ip_flag_fragment, self.ip_TTL, self.ip_protocol, self.ip_checksum, ip_source_IP, ip_dest_IP )
        return ip_header
    def toString(self):
        return ("source IP: %s" % self.source_IP
                    + " \n dest IP : %s"% self.dest_IP
                    +"\n ip version: %d"% self.ip_version
                    + "\n ip IHL: %d"%self.ip_internet_header_length
                    +"\n ip tos: %d"%self.ip_typeOfService
                    +"\n ip total len: %d"%self.ip_total_len
                    +"\n ip flags: %d"%self.ip_flag
                    +"\n ip identification: %d"%self.ip_identification
                    +"\n ip fragment offset: %d"%self.ip_frag_offset
                    + "\n ip TTL: %d"%self.ip_TTL
                    +"\n ip protocol: %d"% self.ip_protocol
                    )
class TCP:
    source_IP = ''
    dest_IP =''
    tcp_source_port = random.randint(30000,60000)   # source port
    tcp_dest_port = 80   # destination port
    tcp_seq = 0
    tcp_ack_seq = 0
    tcp_data_offset = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    tcp_flag_fin = 0
    tcp_flag_syn = 1
    tcp_flag_rst = 0
    tcp_flag_psh = 0
    tcp_flag_ack = 0
    tcp_flag_urg = 0
    tcp_window = socket.htons (5840)    #   maximum allowed window size
    tcp_checksum = 0
    tcp_urgent_pointer = 0    
    tcp_header = ""
    def __init__(self, sourceIP, destIP):
        self.source_IP = sourceIP
        self.dest_IP = destIP
    def setSourceport(self, sourceport = 8888):
        self.tcp_source_port = sourceport
    def setDestPort(self, destport = 80):
        self.tcp_dest_port = destport
    def setSeq(self, sequence = 1):
        self.tcp_seq = sequence
    def setAckSeq(self, AckSeq = 0):
        self.tcp_ack_seq = AckSeq
    def setDataOffset(self, offset = 5):
        self.tcp_data_offset = offset
    def setFlags(self, syn = 1, ack=0, psh=0, fin=0, rst=0,  urg=0):
        self.tcp_flag_fin = fin
        self.tcp_flag_syn = syn
        self.tcp_flag_rst = rst 
        self.tcp_flag_psh = psh 
        self.tcp_flag_ack = ack 
        self.tcp_flag_urg = urg
    def setWindow(self, window = socket.htons(5840)):
        self.tcp_window = socket.htons(window)
    def setCheckSum(self, checksum = 0):
        self.tcp_checksum = checksum
    def setUrgentPointer(self, urgptr = 0):
        self.tcp_urgent_pointer = urgptr
        
    def getTCPheader(self, user_data):
        tcp_offset_res = (self.tcp_data_offset << 4) + 0
        tcp_flags = self.tcp_flag_fin + (self.tcp_flag_syn << 1) + (self.tcp_flag_rst << 2) + (self.tcp_flag_psh <<3) + (self.tcp_flag_ack << 4) + (self.tcp_flag_urg << 5)
        #print tcp_offset_res
       # print tcp_flags
        # the ! in the pack format string means network order
        tcp_header = pack('!HHLLBBHHH' , self.tcp_source_port, self.tcp_dest_port, self.tcp_seq, self.tcp_ack_seq, tcp_offset_res, tcp_flags,  self.tcp_window, self.tcp_checksum, self.tcp_urgent_pointer)
        
        # pseudo header fields
        source_address = socket.inet_aton( self.source_IP )
        dest_address = socket.inet_aton(self.dest_IP)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header) + len(user_data)
        
        psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
        psh = psh + tcp_header + user_data;
        
        tcp_check = baseUtility.checksum(psh)
        #print tcp_check
        
        # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
        tcp_header = pack('!HHLLBBH' , self.tcp_source_port, self.tcp_dest_port, self.tcp_seq, self.tcp_ack_seq, tcp_offset_res, tcp_flags,  self.tcp_window) + pack('H' , tcp_check) + pack('!H' , self.tcp_urgent_pointer)
        return tcp_header        
   
    def congestionWindowAdjust():
        return None
    def toString(self):
        return ("Source Address: %s" % self.source_IP
                    + "\n Dest IP: %s" % self.dest_IP
                    + "\n data offset: %d" % self.tcp_data_offset
                    + "\n tcp source port: %d" % self.tcp_source_port
                    + "\n tcp dest port: %d " %self.tcp_dest_port
                    + "\n tcp seq: %d" % self.tcp_seq
                    + "\n tcp ack seq: %d" %self.tcp_ack_seq
                    +"\n tcp syn flag: %d" % self.tcp_flag_syn
                    +"\n tcp ack flag: %d" % self.tcp_flag_ack
                    +"\n tcp fin flag: %d"% self.tcp_flag_fin
                    +"\n tcp rst  flag: %d" %self.tcp_flag_rst
                    +"\n tcp psh flag: %d" % self.tcp_flag_psh
                    +"\n tcp urg flag: %d" % self.tcp_flag_urg
                    +"\n tcp window: %d" % self.tcp_window
                    ) 
class recvPacket:
    recv_user_data = ""
    recv_source_ip = ""
    recv_dest_ip = ""
    recv_total_len = 0 
    recv_ver_ihl = 0
    recv_ihl = 0
    recv_source_port = 0
    recv_dest_port = 0
    recv_seq = 0
    recv_ack_seq = 0
    recv_window_size = 0
    recv_dataoffset_reserve = 0
    recv_tcphdr_len = 0
    recv_next_expect_seq = 0
    recv_flag_SYN = 0
    recv_flag_ACK = 0
    recv_flag_FIN = 0
    recv_flag_URG = 0
    recv_flag_RST = 0
    recv_flag_PSH = 0
    def __init__(self):
        pass
    
    def setTCPheader(self):
        self.recv_tcphdr_len = self.recv_dataoffset_reserve >> 4
        
    def toString(self):
        return ("source IP: %s"% self.recv_source_ip
                    + "\n dest IP: %s"%self.recv_dest_ip
                    + "\n source port: %d"%self.recv_source_port
                    + "\n dest port: %d"%self.recv_dest_port
                    + "\n recieve seq: %d"%self.recv_seq
                    + "\n recieve ack seq: %d"%self.recv_ack_seq
                    +"\n recieve dataoffset reserve: %d"%self.recv_dataoffset_reserve
                    +"\n recv tcp header len: %d"%self.recv_tcphdr_len
                    +"\n next expected seq: %d"%self.recv_next_expect_seq
                    +"\n recv data : %s \t len: %d"%(self.recv_user_data, len(self.recv_user_data))
                    )
class baseUtility:
    cwnd = 1
    def __init__(self):
        pass
    # getFileName(_url)
    #  If URL has a file with extension like 
    # http://david.choffnes.com/classes/cs4700sp16/project4.php
    # file name is project4.php
    # else  the filename is default index.html    
    @staticmethod
    def getFileName(_url):
        filename = "index.html"   
        _path = urlparse.urlparse(_url).path
        if not _path:
            filename = "index.html"
        if len(_path.rsplit('/',1)) > 1:
            filename = _path.rsplit('/',1)[-1]
        return filename
    
    # data is the HTML body of HTTP response
    @staticmethod
    def createFile(_url, _data):
        filename = baseUtility.getFileName(_url)
        try:
            downloadfile = open(filename, 'w')
            downloadfile.write(_data)
        except IOError as e:
            print e.message
        finally:
            downloadfile.close()    
    @staticmethod
    def getIPofHost(host):
        return socket.gethostbyname(host)
    @staticmethod
    def getHostName(url):
        return urlparse.urlparse(url).netloc 
    @staticmethod
    def checksum(msg):
        s = 0
        msg = baseUtility.dataLenProcess(msg)
        # loop taking 2 characters at a time
        for i in range(0, len(msg), 2):
            w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
            s = s + w
         
        s = (s>>16) + (s & 0xffff);
        s = s + (s >> 16);
        #complement and mask to 4 byte short
        s = ~s & 0xffff
         
        return s    
    @staticmethod
    def getLocalIP(network_interface):
        sock = customerSocket.udpSock()
        return socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, pack('256s', network_interface[:15]))[20:24] )
    @staticmethod
    def isPacketQulified(recieve_data, source_IP, destIP, source_port, dest_port, flag):
        pkt = baseUtility.unPackPacket(recieve_data[0],source_IP,destIP)
        #print pkt.toString()
        if flag:
            if pkt.recv_source_ip == destIP and pkt.recv_dest_ip == source_IP:
                return True
        else:
            if pkt.recv_source_ip == destIP and pkt.recv_dest_ip == source_IP and len(recieve_data[0]) > 44 or pkt.recv_flag_FIN  == 1 :
                return True              
        return False
    
    @staticmethod
    def unPackPacket(pktStr,sip,dip):
        pkt = recvPacket()
        tcph = ""
        tcp_header = ""
        ip_header = pktStr[0:20]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        pkt.recv_ver_ihl = iph[0] 
        pkt.recv_ihl = pkt.recv_ver_ihl & 0x0f 
        pkt.recv_total_len = iph[2]
        pkt.recv_source_ip = socket.inet_ntoa(iph[8])
        pkt.recv_dest_ip = socket.inet_ntoa(iph[9])
        ipheader = pktStr[0: pkt.recv_ihl*4]
        if baseUtility.checksum(ipheader) != 0:
            print ("IP checksum error")
        
        tcp_header = pktStr[20:40]
        tcph = unpack('!HHLLBBHHH' , tcp_header)
        pkt.recv_source_port = tcph[0]
        pkt.recv_dest_port = tcph[1] 
        pkt.recv_seq = tcph[2]
        pkt.recv_ack_seq = tcph[3]
        pkt.recv_dataoffset_reserve = tcph[4]
        dataoffset = pkt.recv_dataoffset_reserve >> 4
        pkt.recv_user_data = pktStr[40:]
        flags = tcph[5]
        pkt.recv_flag_FIN = flags & 0x01
        pkt.recv_flag_SYN = (flags & 0x02) >> 1
        pkt.recv_flag_RST = (flags & 0x04) >> 2
        pkt.recv_flag_PSH = (flags & 0x08) >> 3
        pkt.recv_flag_ACK = (flags & 0x10) >> 4
        pkt.recv_flag_URG = (flags & 0x20) >> 5        
        pkt.recv_window_size = tcph[6]                 
        pkt.recv_next_expect_seq = pkt.recv_seq + len(pkt.recv_user_data)

        return pkt
    @staticmethod
    def dataLenProcess(user_data):
        if len(user_data) %2 != 0:
            return user_data + "0"
        return user_data
    @staticmethod
    def reciveData(receive_sock, sourceIP, destIP,tcp_source_port, dest_port, flag=True):
        Packets_of_this_program = []
        start_time = time.time()
        while time.time() - start_time < 180:
            try:
                data = receive_sock.recvfrom(65535)
                if baseUtility.isPacketQulified(data, sourceIP, destIP, tcp_source_port, dest_port, flag):
                    Packets_of_this_program.append(data[0])
                    return Packets_of_this_program
            except:
                continue
        baseUtility.cwnd =1
        print "TIME OUT ERROR"
        
    @staticmethod
    def tcpHandShake(tcp_obj, ip_obj,receive_sock,send_sock,sourceIP,destIP):
        baseUtility.sendInitSyn(tcp_obj, ip_obj,send_sock,destIP)
        Packets_of_this_program = baseUtility.reciveData(receive_sock, sourceIP,destIP,  tcp_obj.tcp_source_port,tcp_obj.tcp_dest_port)
        recv_packet = baseUtility.unPackPacket(Packets_of_this_program[0],sourceIP,destIP) 
        recv_packet.recv_user_data = ""
        baseUtility.sendAck(tcp_obj, ip_obj, send_sock, destIP, sourceIP,receive_sock,recv_packet)
        if  baseUtility.cwnd < 1000:
                    baseUtility.cwnd +=1        
         
    @staticmethod
    def sendInitSyn(tcp_obj, ip_obj,send_sock,destIP):
        ip_header = ip_obj.getIPheader()
        tcp_header = tcp_obj.getTCPheader("")
        #print tcp_obj.toString()
        packet = ip_header + tcp_header + ""
        send_sock.sendto(packet,(destIP,0))
    @staticmethod
    def sendAck(tcp_obj, ip_obj,send_sock,destIP, sourceIP, receive_sock, recv_packet, flag = True,Fin = False,  user_data = ""):
        ip_header = ip_obj.getIPheader()
        tcp_obj.setWindow(min(recv_packet.recv_window_size, tcp_obj.tcp_window ))
        tcp_obj.setAckSeq(recv_packet.recv_seq + len(recv_packet.recv_user_data)+1)
        if len(recv_packet.recv_user_data) != 0 and len(recv_packet.recv_user_data) > 40:
            tcp_obj.setAckSeq(recv_packet.recv_seq + len(recv_packet.recv_user_data))
        tcp_obj.setSeq(recv_packet.recv_ack_seq)
        tcp_obj.setFlags(syn=0, ack=1)
        if Fin:
            tcp_obj.setFlags(syn=0,ack=1,psh=0,fin=1)
        tcp_obj.tcp_header = tcp_obj.getTCPheader(user_data)          
        packet = ip_header + tcp_obj.tcp_header + user_data
        send_sock.sendto(packet,(destIP,0))
        return (tcp_obj, recv_packet)
    @staticmethod
    def sendPacket(tcp_obj, ip_obj,send_sock,destIP,data_to_send):
        ip_header = ip_obj.getIPheader()
        tcp_obj.setFlags(syn=0, ack=1, psh=1)
        data_to_send = baseUtility.dataLenProcess(data_to_send)
        tcp_header = tcp_obj.getTCPheader(data_to_send)
        packet = ip_header + tcp_header + data_to_send
        send_sock.sendto(packet,(destIP,0))             
    @staticmethod
    def dataGramRecieve(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock,currentData):
        #filter out the correct packets contains with data
        #loop ack to server
        Expected_Seq = 0
        data = ""
        init_packet = baseUtility.reciveData(receive_sock, sourceIP, destIP, tcp_obj.tcp_source_port, tcp_obj.tcp_dest_port, False) 
        init_unpack_packet = baseUtility.unPackPacket(init_packet[0], sourceIP, destIP)
        data = init_unpack_packet.recv_user_data
        baseUtility.sendAck(tcp_obj, ip_obj, send_sock, destIP, sourceIP,  receive_sock,   init_unpack_packet,False)
        if baseUtility.cwnd < 1000:
            baseUtility.cwnd +=1
        Expected_Seq = init_unpack_packet.recv_next_expect_seq
        start_time = time.time()
        while time.time() - start_time < ACK_TIME_OUT:
            try:
                packets = baseUtility.reciveData(receive_sock, sourceIP, destIP,   tcp_obj.tcp_source_port,   tcp_obj.tcp_dest_port, False)
            except:
                continue
            packet = baseUtility.unPackPacket(packets[0], sourceIP, destIP)

            if packet.recv_flag_FIN == 1:      
                data += packet.recv_user_data
                baseUtility.sendAck(tcp_obj, ip_obj, send_sock, destIP, sourceIP,  receive_sock,  packet,False)
                if baseUtility.cwnd < 1000:
                            baseUtility.cwnd +=1                
                baseUtility.sendAck(tcp_obj, ip_obj, send_sock, destIP, sourceIP,  receive_sock,  packet,False,True)
                break
            if packet.recv_seq == Expected_Seq:
                data += packet.recv_user_data
                Expected_Seq = packet.recv_next_expect_seq
                baseUtility.sendAck(tcp_obj, ip_obj, send_sock, destIP, sourceIP,  receive_sock,  packet,False)
                if baseUtility.cwnd < 1000:
                            baseUtility.cwnd +=1
                start_time = time.time()
            else:
                baseUtility.cwnd = 1
                start_time = time.time()
                continue
            if "\n0\r\n"  in data:
                break

        return data
    @staticmethod
    def recv(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock, currentData):
        data = baseUtility.dataGramRecieve(tcp_obj, ip_obj, send_sock, destIP, sourceIP, receive_sock,currentData)
        return data 
def highlevelTest(url):
    http = HTTP()
    host = urlparse.urlparse(url).netloc 
    httpRequestHeader = http.GETRequest(url)
    sock_obj = customerSocket()
    sock = sock_obj.normalSocket()
    sock.connect((host, 80))
    sock.send(httpRequestHeader)
    response = sock_obj.recieve(sock)
    htmlHeader,htmlBody = http.responseSplit(response)
    if http.isStatus200(htmlHeader):
        #createFile(url,htmlBody)
        baseUtility.createFile(url,htmlBody)
    else:
        print ("The HTTP response is abnormal, please check your code!")
def lowLevelTest(url):
    data_to_send = HTTP.GETRequest(url)
    send_sock = customerSocket.senderSocket()
    receive_sock = customerSocket.rawRecvSock()
    dest_host_name = baseUtility.getHostName(url)
    sourceIP = baseUtility.getLocalIP("eth0")
    destIP = baseUtility.getIPofHost(dest_host_name)   
    ip_obj = IP(sourceIP, destIP)
    
    #print ip_obj.toString()
    tcp_obj = TCP(sourceIP, destIP)
    tcp_obj.setFlags()
    baseUtility.tcpHandShake(tcp_obj, ip_obj, receive_sock, send_sock, sourceIP, destIP)
    baseUtility.sendPacket(tcp_obj, ip_obj, send_sock, destIP, data_to_send)
    data = customerSocket.recieve(tcp_obj, ip_obj, send_sock, destIP,  sourceIP, receive_sock)
    htmlHeader,htmlBody = HTTP.responseSplit(data)
    if HTTP.isStatus200(htmlHeader):
        #createFile(url,htmlBody)
        baseUtility.createFile(url,htmlBody)    
    return None

def main(arg):
    if arg: 
        url = arg[-1]
    else:
        url = "www.ccs.neu.edu"
    #highlevelTest(url)
    lowLevelTest(url)
    
if __name__ == "__main__":
    main(sys.argv[1:])