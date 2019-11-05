
tcp_message = b'|Transport header|Request https://192.168.0.7/test.txt HTTPS:\r\nHost: 192.168.0.7\r\nFile: test.txt\r\nAccept: text\r\n\r\n'

ip_packet0 = b'\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc0\xa8\x00\x02\xc0\xa8\x00\x07|Transport header|Request https://192.168.0.7/test.txt HTTPS:\r\nHost: 192.168.0.7\r\nFile: test.txt\r\nAccept: text\r\n\r\n'

request = b'Request https://192.168.0.7/test.txt HTTPS:\r\nHost: 192.168.0.7\r\nFile: test.txt\r\nAccept: text\r\n\r\n'

from code_and_decode import *

ip_packet = encode_IP_segment('192.168.0.7','192.168.0.2') + tcp_message

if ip_packet0 == ip_packet:
    print('True')
message, dic = decode_IP_segment(ip_packet)
print(message,dic)

# body,dic_appli = decode_appli_message(request)


# print(body,dic_appli)
