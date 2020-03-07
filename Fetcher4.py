# This Application is intended to Analyze  network traffic and print the useful metadata
# Written by Hamad ALSHEHHI
# 14 December 2014
# Singapore

import pcapy, copy, datetime, time as timey, sys, multiprocessing, os, argparse, zlib,gzip


def toNum(val):
        out = 0
        for x in val:
                out = (out << 8) | ord(x)
        return out


if (__name__ == '__main__'):
        # parse args here
        parser = argparse.ArgumentParser(
                description="This program intended for analyzing network traffic and print the usefull metadata")
        parser.add_argument("pcapfileName", help="The name of the pcap with traffic")
       args = parser.parse_args()
        reader = pcapy.open_offline(args.pcapfileName)
        i = 0
        while True:
                try:
                        i += 1
                        header, payload = reader.next()
                        time = header.getts()
                        time = (time[0] * 1000) + (time[1] / 1000)
                        ethernet = payload[0:14]
                        ip = payload[14:34]
                        tcp = payload[34:]
                        sourceport = toNum(tcp[0:2])
                        destport = toNum(tcp[2:4])
                        seqnum = tcp[4:8]
                        acknum = tcp[8:12]
                        tcpheaderLen = (((ord(tcp[12]) & 0xf0) >> 4) & 0xf) * 4
                        print("packet:" + str(i) + " src ip:" + str(ord(ip[12])) + "." + str(ord(ip[13])) + "." + str(
                                ord(ip[14])) + "." + str(ord(ip[15])) + " port:" + str(sourceport) + " dst ip:" + str(
                                ord(ip[16])) + "." + str(ord(ip[17])) + "." + str(ord(ip[18])) + "." + str(
                                ord(ip[19])) + " port:" + str(destport));
                        print (payload [2:])
                        print ('\n')
                     #   decompressed_data=zlib.decompress(payload, 16+zlib.MAX_WBITS)
                      #  print ("gzip> ",decompressed_data)

                      #  data = gzip.decompress(payload)
                       # data = str(data,'utf-8')

                except pcapy.PcapError:
                        break

