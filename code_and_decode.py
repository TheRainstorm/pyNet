# 应用层
def encode_request(url):
    protocal,_,d_ip,file = url.split('/')
    file_ex = file.split('.')[1]

    #构造请求头
    Header = ''
        #first line
    Header += 'Request '+url+' '+protocal.upper()+'\r\n'
        #key value
    Host = d_ip
    File = file
    Accept = {'txt':'text','png':'img','jpg':'img'}[file_ex]
    dic = {'Host':Host,'File':File,'Accept':Accept}
    for key,value in dic.items():
        Header += key+': '+value+'\r\n'
    Header += '\r\n'
        #body(empty)
    Body = b'' 
        
    Message = Header.encode('utf-8')+Body

    return Message,d_ip

def encode_response(State,dic,Body):
    #构造响应头
        #first line
    if State:
        Header = 'Response '+'200'+' '+'OK'+'\r\n'
    else:
        Header = 'Response '+'404'+' '+'Not Found'+'\r\n'
        #key value
    for key,value in dic.items():
        Header += key+': '+value+'\r\n'
    Header += '\r\n'

    Message = Header.encode('utf-8')+Body

    return Message

def decode_appli_message(message):
    N = len(message)
    i = 0
    while(i <= N-4):
        if message[i:i+4]==b'\r\n\r\n':
            header_end_i = i
            body_start_i = i+4
        i += 1
    header = message[:header_end_i]
    body = message[body_start_i:]

    dic ={}
    L = header.decode('utf-8').split('\r')
    L = [e.strip() for e in L]
    first_line = L[0].split(' ') #第一行的3个元素
    if first_line[0] == 'Request':
        url = first_line[1]
        protocal = first_line[2]
        dic['type']='Request'
        dic['url'] = url
        dic['protocal'] = protocal

        # {'Host':Host,'File':File'Accept':Accept}
        for line in L[1:]:
            key,value = line.split(' ')
            key = key[:-1] # exclude ':'
            dic[key]=value
    else:
        state_code = first_line[1]
        description = first_line[2]
        dic['type']='Response'
        dic['state_code'] = state_code
        dic['description'] = description

        for line in L[1:]:
            key,value = line.split(' ')
            key = key[:-1] # exclude ':'
            dic[key]=value

    return body,dic

# 传输层
def decode_trans_message(message):
    trans_header = '|Transport header|'

    message_appli = message[len(trans_header):]

    dic = {}
    dic['header'] = trans_header
    return message_appli,dic


# 网络层
def encode_1st(version, szHeader, server_type, szWhole):
    return int.to_bytes((version * 16 + szHeader), 1, 'little') + int.to_bytes(server_type, 1, 'little') + int.to_bytes(szWhole, 2, 'little');

def encode_2nd(identi, flag, sliceOffset):
    return int.to_bytes(identi, 2, 'little') + int.to_bytes((flag * 8192 + sliceOffset), 2, 'little');

def encode_3rd(TTL, protocol, Inspection_head):
    return int.to_bytes(TTL, 1, 'little') + int.to_bytes(protocol, 1, 'little') + int.to_bytes(Inspection_head, 2, 'little');

# ip是字符串;
def encode_ip(ip):
    p0 = ip.split(".");
    p1 = map(int, p0);
    p2 = bytes();
    for p in p1:
        # p2 = p2 + intTobytes(p);
        p2 += int.to_bytes(p,1,byteorder='little')
    return p2;

def encode_IP_segment(d_ip,ip, version=1, szHeader=0, server_type=0, szWhole=0, identi=0, flag=0, sliceOffset=0, TTL=0, protocol=0, Inspection_head=0):
    return encode_1st(version, szHeader, server_type, szWhole) + encode_2nd(identi, flag, sliceOffset) + encode_3rd(TTL, protocol, Inspection_head) + encode_ip(ip) + encode_ip(d_ip);
# 解封装IP数据报的第一行
def decode_1st(byte):
    version_int = byte[0] // 16;
    sizeOfHeader_int = byte[0] % 16;
    server_type_int = byte[1];
    whole_size_int = int.from_bytes(byte[2:],'little');
    return version_int, sizeOfHeader_int, server_type_int, whole_size_int;

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
    message = ip_packet[20:];
    ip_Header = ip_packet[:20];
    dic = {};
    dic["版本号:"], dic["首部长度"], dic["区分服务"], dic["总长度"] = decode_1st(ip_packet[0:5]);
    dic["标识"], dic["标志"], dic["片偏移"] = decode_2nd(ip_packet[5:10]);
    dic["生存时间"], dic["协议"], dic["首部检验和"] = decode_3rd(ip_packet[10:15]);
    dic["源地址"] = decode_ip(ip_packet[15:20]);
    dic["目的地址"] = decode_ip(ip_packet[20:]);
    return message, dic;


#数据链路层
def encode_mac(mac):
    return int.to_bytes(mac,6,byteorder='little')

def encode_frame(d_mac,s_mac,ip_packet):
    FCS = b'\x00\x00\x00\x00'
    frame = encode_mac(d_mac)+encode_mac(s_mac)+b'ip'+\
                ip_packet+ FCS#encode_mac()返回6字节，48位
    return frame
def decode_frame(frame):
    # 目的mac，源mac
    d_mac,s_mac = frame[0:6],frame[6:12]
    # 协议类型（只有ip)
    protocol = frame[12:14] # b'ip'
    # 尾部帧校验序列
    FCS = frame[-4:]

    # 上层ip packet
    ip_packet = frame[14:-4]

    dic = {}
    dic['d_mac']=d_mac
    dic['s_mac']=s_mac
    dic['protocol']=protocol
    dic['FCS']=FCS

    return ip_packet,dic