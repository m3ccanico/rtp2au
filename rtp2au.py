import dpkt
import hexdump
import socket
import datetime

# packet capture file to read
p = open('dsp.pcap01')
# au file to write
o = open('radio.au', 'w')
# multicast IP to look for
dst = "239.230.9.42"
# UDP port to look for
udp_port = 21000

dst_n = socket.inet_aton(dst)
pcap = dpkt.pcap.Reader(p)

# after how many packets (50pps in RTP) to stop including silence (compacting stream by supression silence that is longer than 3s)
max_silence = 150
# expect an RTP packet very 20ms
time_offset_between_packets = 0.02

# write AU header
o.write("\x2e\x73\x6e\x64") # AU magic header #0x2e736e64 
o.write("\x00\x00\x00\x24") # offset for audio = length of header (6 byte)
o.write("\xff\xff\xff\xff") # length of payload (unknown)
o.write("\x00\x00\x00\x01") # encoding: G.711
o.write("\x00\x00\x1f\x40") # sampling rate: 8000
o.write("\x00\x00\x00\x01") # channels: mono

i = 0

for ts, buf in pcap:
    if i == 0:
        last = ts
    #print "%.3f" % ts

    eth = dpkt.ethernet.Ethernet(buf)
    if eth.type == 0x800:
        ip = eth.data

        # only process the expected multicast stream with UDP payload
        if ip.dst == dst_n and ip.p == 17:
            udp = ip.data

            # only process datagrams with the correct UDP port
            if udp.dport == udp_port:
                rtp = dpkt.rtp.RTP(udp.data)

                if rtp.pt == 110:
                    # seames to be used for signalling the identity of the sender in my test file -> ignore it
                    time = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')
                    offset = datetime.datetime.fromtimestamp(i * time_offset_between_packets).strftime('%M:%S')
                    print "new talker at %s, offset: %s, %s" % (time, offset, rtp.data.replace("\n", " "))
                elif rtp.pt == 0:
                    silence_cnt = 0
                    # if the next packet is later the the normal RTP timeout plus some tolerance (10%) start adding silence
                    while ts - last > time_offset_between_packets*1.1:
                        #print "add silence %d" % len(160*"\x00")
                        o.write(160*"\x00")
                        last += time_offset_between_packets
                        silence_cnt += 1
                        i += 1
                        # stop adding silence when max_silence is reached
                        if silence_cnt > max_silence:
                            last = ts - time_offset_between_packets
                            time = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')
                            #print "jump  %s" % time
                            break
                    time = datetime.datetime.fromtimestamp(ts).strftime('%H:%M:%S.%f')
                    #print "voice %s, %d, %s" % ( time, len(rtp.data), socket.inet_ntoa(ip.src) )
                    o.write(rtp.data)
                    last = ts
                    i += 1
                else:
                    print "don't understand RTP payload type"

                #if i > 100:
                #    break

p.close()
o.close()
