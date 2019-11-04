def encode_1st(version, szHeader, server_type, szWhole):
    return int.to_bytes((version * 16 + szHeader), 1, 'little') + int.to_bytes(server_type, 1, 'little') + int.to_bytes(szWhole, 2, 'little');

def encode_2nd(identi, flag, sliceOffset):
    return int.to_bytes(identi, 2, 'little') + int.to_bytes((flag * 8192 + sliceOffseteOffset), 2, 'little');

def encode_3rd(TTL, protocol, Inspection_head):
    return int.to_bytes(TTL, 1, 'little') + int.to_bytes(protocol, 1, 'little') + int.to_bytes(Inspection_head, 2, 'little');

# ip是字符串;
def encode_ip(ip):
    p0 = ip.split(".");
    p1 = map(int, p0);
    p2 = bytes();
    for p in p1:
        p2 = p2 + intTobytes(p);
    return p2;

def encode_IP_segment(version, szHeader, server_type, szWhole, identi, flag, sliceOffset, TTL, protocol, Inspection_head, ip, d_ip):
    return encode_1st(version, szHeader, server_type, szWhole) + encode_2nd(identi, flag, sliceOffset) + encode_3rd(TTL, protocol, Inspection_head) + encode_ip(ip) + encode_ip(d_ip);
# 解封装IP数据报的第一行
def decode_1st(byte):
    version_int = byte[0] // 16;
    sizeOfHeader_int = byte[0] % 16;
    server_type_int = byte[1];
    whole_size_int = int.from_bytes(b[2:],'little');
    return version_int, sizeOfHeader_int, server_type, whole_size_int;

def decode_2nd(byte):
    identi = byte[0] * 256 + byte[1];
    flag = int.from_bytes(byte[2:], 'little') // 8192;
    sliceOffset = int.from_bytes(byte[2:], 'little') % 8192;
    return identi, flag, sliceOffset;
    
def decode_3rd(byte):
    TTL = byte[0];
    protocol = byte[1];
    Inspection_head = int.from_bytes(byte[2:], 'little');
    return TTL, protocol, Inspection_head;

def decode_ip(byte):
    ip = str(byte[0]);
    for i in range(1,4):
        ip = ip + '.' + str(byte[i]);
    return ip;

def decode_IP_segment(ip_packet):
    message = ip_packet[45:];
    ip_Header = ip_packet[:25];
    dic = {};
    dic["版本号:"], dic["首部长度"], dic["区分服务"], dic["总长度"] = decode_1st(ip_packet[0:5]);
    dic["标识"], dic["标志"], dic["片偏移"] = decode_2nd(ip_packet[5:10]);
    dic["生存时间"], dic["协议"], dic["首部检验和"] = decode_3rd(ip_packet[10:15]);
    dic["源地址"] = decode_ip(ip_packet[15:20]);
    dic["目的地址"] = decode_ip(ip_packet[20:]);
    return message, dic;