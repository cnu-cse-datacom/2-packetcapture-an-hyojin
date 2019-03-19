import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_ethernet_address(ethernet_header[0:6])
    ether_dest = convert_ethernet_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("======ethernet header======")
    print("src_mac_address:", ether_src)
    print("dest_mac_address:", ether_dest)
    print("ip_version", ip_header)

def convert_ethernet_address(data):
    ethernet_addr = list()
    for i in data:
        ethernet_addr.append(i.hex())
    ethernet_addr = ":".join(ethernet_addr)
    return ethernet_addr
    
recv_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

while True:
    data = recv_socket.recvfrom(65565)
    parsing_ethernet_header(data[0][0:14])
    ip_header = struct.unpack("!BBHHHBB2s4s4s", data[0][14:34])
    ip_version = (ip_header[0]&0b11110000)>>4
    ip_Length = (ip_header[0]&0b00001111)
    differentiated_service_codepoint = (ip_header[1]&0b11111100)>>2
    explicit_congestion_notification = (ip_header[1]&0b00000011)
    total_length = ip_header[2]
    identification = ip_header[3]
    flags = (ip_header[4]&0xE000)>>13
    reserved_bit = (flags&0b100)>>2
    dont_fragment = (flags&0b010)>>1
    more_fragment = (flags&0b001)
    fragment_offset = ip_header[4]&0x1fff
    time_to_live = ip_header[5]
    protocol = ip_header[6]
    header_checksum = ip_header[7].hex()
    source_Address = socket.inet_ntoa(ip_header[8])
    dest_Address = socket.inet_ntoa(ip_header[9])
    print("=========ip_header==========")
    print("ip_version : ", ip_version)
    print("ip_Length : " , ip_Length)
    print("differentiated_service_codepoint:", differentiated_service_codepoint)
    print("explicit_congestion_notification:",explicit_congestion_notification)
    print("total_length", total_length)
    print("identification", identification)
    print("flags", flags)
    print(">>>reserved_bit : ", reserved_bit)
    print(">>>not_fragment : ", dont_fragment)
    print(">>>fragments: ", more_fragment)
    print(">>>fragment_offset :", fragment_offset)
    print("Time to live: ", time_to_live)
    print("protocol:", protocol)
    print("header_checksum : 0x", header_checksum)
    print("source_ip_address: ",source_Address)
    print("dest_ip_address : ", dest_Address)
    start = ip_Length + 14
    if(protocol ==6):
        tcp_header = struct.unpack("!HHIIBBHHH",data[0][start:start+20] )
        src_port = tcp_header[0]
        dec_port = tcp_header[1]
        seq_num = tcp_header[2]
        ack_num = tcp_header[3]
        header_len = (tcp_header[4]&0b11110000)>>4
        flags = tcp_header[5]
        reserved = (tcp_header[4]&0b00001110)>>1
        nonce = tcp_header[4]&0b00000001
        cwr = (flags&0b10000000)>>7
        urgent = (flags&0b0100000)>>5
        ack = (flags&0b0010000)>>4
        push = (flags&0b00001000)>>3
        reset = (flags&0b00000100)>>2
        syn = (flags&0b00000010)>>1
        fin = flags&0b00000001
        window_size_value = tcp_header[6]
        checksum = tcp_header[7]
        urgent_pointer = tcp_header[8]
        print("=========TCP header=========")
        print("src_port :", src_port)
        print("dec_port :", dec_port)
        print("seq_num : ", seq_num)
        print("ack_num : ", ack_num)
        print("header_len :", header_len)
        print("flags : ", flags)
        print(">>>reserved :", reserved)
        print(">>>nonce:", nonce)
        print(">>>cwr : ", cwr)
        print(">>>urgent : ", urgent)
        print(">>>ack :", ack)
        print(">>>push :", push)
        print(">>>reset : ", reset)
        print(">>>syn : ", syn)
        print(">>>fin : ", fin)
        print("window_size_value:",window_size_value)
        print("checkusm:", checksum)
        if(urgent==1):
            print("urgent_pointer", urgent_pointer)
        else:
            print("urgent_pointer", 0)
        
    if(protocol == 17):
        udp_header = struct.unpack("!HHH2s",data[0][start:start+8])
        source_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        checksum = udp_header[3].hex()
        print("========udp_header=========")
        print("src_port:", source_port)
        print("dst_port:", dest_port)
        print("leng:", length)
        print("header checksum", checksum)
        


    
