import tkinter as tk
from PIL import Image, ImageTk
from skimage import io
import matplotlib.pyplot as plt
import time
import random
import os
import base64

from code_and_decode import *

MAC=0 #每次自增1，确保每台机器mac不同
B_MAC=2**48-1 #broadcast mac

LEN = 350 #length to show 

if not os.path.exists('tmp'):
    os.makedirs('tmp')
def transmit(bitstream, __d_net_ip):
    net_tag_id =int(__d_net_ip.split('.')[-2])
    # print(net_tag_id)
    with open('tmp/bitstream','wb') as file:
        file.write(bitstream)

    def broadcast_to_net(net_tag_id):
        for host_tag_id in net_list[net_tag_id].child_hosts:
            host_list[host_tag_id].service()
        for router_tag_id,port in net_list[net_tag_id].child_routers:
            router_list[router_tag_id].read(port)
    broadcast_to_net(net_tag_id)

def ARP(self_ip, self_mac, req_ip, req='req'):
    '''req取值:'req','rsp',表示是请求还是响应'''
    if req=='req':
        msg = '\n\n%s向%s发出ARP请求\n'%(self_ip,req_ip)
    else:
        msg = '\n\n%s响应来自%s的ARP请求\n'%(self_ip,req_ip)
    append_message(msg)
# 网络层(ARP协议)
    ip_header = encode_IP_segment(d_ip=req_ip, ip=self_ip, protocol=255)
    ip_data = (req+'|'+self_ip+'|'+mac_to_str(self_mac)+'|'+req_ip).encode('utf-8')

    ip_packet = ip_header + ip_data
# 数据链路层 
    d_mac = B_MAC #全为1, 广播
    frame = encode_frame(d_mac,self_mac,ip_packet)
# 物理层
    bitstream = b'START'+frame
    msg = '\n物理层 bitstream:\n%s'%bitstream[:LEN]

    # put the bitstream on the bus
    __d_net_ip = extract_net_ip(req_ip) #can't see
    transmit(bitstream, __d_net_ip) #在指定网络内发射

# class router_table:
#     def __init__(self):
#         self.data={}

class Host:
    def __init__(self,tag_id,canvas):
        global MAC
        self.mac = MAC;MAC+=1
        self.ip = '0.0.0.0'
        self.router_table = {} #路由表
        self.mac_cache = {} #mac 缓存

        #协议栈数据传递
        # # 网络层
        # self.d_ip = '' # 本次请求目的ip
        # # 数据链路层
        # self.d_mac = 0 # 下一站mac
        # self.next_ip = ''
        self.cache = b'' # ip packet slice 解析后的运输层报文缓存

        # 画图使用
        self.canvas=canvas
        self.tag_id = tag_id
        self._width = 48
        self._height = 48
        self.x = 0 # image center place, left top,left top,left top as origin
        self.y = 0
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_host)
        global item_to_instance_dic
        item_to_instance_dic[self.id]=self

    def move_to(self,pos): # pos: (x,y), origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))
        self.x,self.y = pos[0]+self._width/2,des_y+self._height/2

    def service(self): # 应用层文件服务
        flag, message, s_ip = self.rcv()
        if 0==flag: #不是自己的消息/或ip packet还未集齐
            return 0

        #应用层
        body,dic_appli = decode_appli_message(message)

        #is Request
        if dic_appli['type']=='Request':
            msg = '\nhost: %s get request from host: %s\n'%(self.ip,s_ip)
            append_message(msg)

            # response
            File = dic_appli['File']
            Accept = dic_appli['Accept']
            
            if os.path.exists('src/'+File):
                State = 1 #可响应，200 ok

                file_ex = File.split('.')[1]
                FileType = {'txt':'text','png':'img','jpg':'img'}[file_ex]
                with open('src/'+File,'rb') as fp:
                    Body = fp.read()

                if FileType=='img': #图片
                    Body = base64.b64encode(Body)

                def get_FileSize(filePath):
                    fsize = os.path.getsize(filePath)
                    if fsize<1024:
                        return str(fsize)+'B'
                    elif fsize<1024*1024:
                        return str(round(fsize/1024.0,2))+'KB'
                    else:
                        return str(round(fsize/1024.0/1024.0,2))+'MB'
                FileSize = get_FileSize('src/'+File)
                
                dic = {}
                dic['File'] = File
                dic['FileSize']=FileSize
                dic['FileType']=FileType
            else:
                State = 0 #404 not found
                dic = {}
                Body = b'' # empty

            message = encode_response(State,dic,Body)
            # print(message)
            msg = '\n应用层报文:\n%s'%message
            if len(msg)>LEN:
                msg = msg[:LEN]+'......\n'
            append_message(msg)

            self.send(s_ip,message)

        # is Response
        elif dic_appli['type']=='Response':
            msg = '\nhost: %s get response from host: %s\n'%(self.ip,s_ip)
            append_message(msg)

            # show
            from uuid import uuid1
            if dic_appli['state_code']!='200':
                print(dic_appli['state_code']+dic_appli['description'])
            elif dic_appli['FileType']=='text':
                print(body.decode('utf-8'))
            elif dic_appli['FileType']=='img':
                file_name = dic_appli['File']
                file_ex = file_name.split('.')[1]
                u_name = str(uuid1())+'.'+file_ex
                with open('tmp/'+u_name,'wb') as fp:
                    fp.write(base64.b64decode(body))
                img = io.imread('tmp/'+u_name)
                io.imshow(img)
                io.show()
            else:
                print('File type don\'t support!\n')
        else:
            print('\napplication message mess!\n')

    # def client(self,url):
    def request(self,url):
    # 应用层
        message,d_ip = encode_request(url)

        msg = '\n应用层报文:\n%s'%message[:LEN]
        if len(message)>LEN:
            msg += '...\n'
        append_message(msg)

        self.send(d_ip,message)

    def send(self,d_ip,message): #封装到运输层
    # 运输层
        message = '|Transport header|'.encode('utf-8')+message
        msg = '\n运输层:\n%s'%message[:LEN]
        if len(message)>LEN:
            msg += '...\n'
        append_message(msg)
    # 网络层
        ip_packet_queue = slice(message,d_ip,self.ip,MTU=1400)
        for i,ip_packet in enumerate(ip_packet_queue):
            if i<2:
                msg = '\n网络层 sending packet slice %d:\n'%(i)
                msg += '%s'%ip_packet[:LEN]
                if len(ip_packet)>LEN:
                    msg += '...\n'
                append_message(msg)
            elif i==len(ip_packet_queue)-1:
                msg = '\n网络层 sending last packet slice %d:\n'%(i)
                msg += '...%s\n'%ip_packet[-LEN:]
                append_message(msg)
            else:
                append_message('sending packet slice %d...\n'%(i))

            d_net_ip = extract_net_ip(d_ip)
            if d_net_ip==extract_net_ip(self.ip): # 同一局域网
                next_ip = d_ip
            else: # 查找路由表
                if self.router_table.get(d_net_ip)==None:
                    next_ip = self.router_table['default'] # 默认网关
                else:
                    next_ip = self.router_table[d_net_ip]

            # search cache for mac or use ARP
            while(1):
                if self.mac_cache.get(next_ip)==None:
                    # print('error,host can\'t find mac')
                    #ARP
                    ARP(self.ip, self.mac, next_ip)
                else:
                    d_mac = self.mac_cache[next_ip]
                    break
        # 数据链路层
            frame = encode_frame(d_mac,self.mac,ip_packet)
            if i == 0:
                msg = '\n数据链路层 frame:\n%s'%frame[:LEN]
                if len(frame)>LEN:
                    msg += '...\n'
                append_message(msg)
        # 物理层
            bitstream = b'START'+frame
            if i == 0:
                msg = '\n物理层 bitstream:\n%s'%bitstream[:LEN]
                if len(bitstream)>LEN:
                    msg += '...\n'
                append_message(msg)

            # put the bitstream on the bus
            __d_net_ip = extract_net_ip(next_ip) #can't see
            transmit(bitstream, __d_net_ip) #在指定网络内发射
    def rcv(self):
    # 物理层
        with open('tmp/bitstream','rb') as file:
            START = file.read(5)
            if START!=b'START':
                print('\nbitstream error\n')

            d_mac_bys = file.read(6)
            d_mac = int.from_bytes(d_mac_bys,byteorder='little')
            if d_mac != B_MAC and d_mac!=self.mac:
                return 0,b'',''  #不是自己的消息，退出
            else:
                frame = d_mac_bys+file.read()
    # 数据链路层
        ip_packet,dic_fra = decode_frame(frame)
    #网络层
        message, dic_net =decode_IP_segment(ip_packet)
        #ARP 协议
        if dic_net['协议']==255:
            ARP_message = message.decode('utf-8')
            #解析ARP
            req, src_ip, src_mac, req_ip = ARP_message.split('|')
            self.mac_cache[src_ip] = macstr_to_int(src_mac) #更新mac缓存

            if req=='req' and req_ip==self.ip: #返回一个ARP响应
                ARP(self.ip, self.mac, src_ip, req='rsp')
            return 0,b'',''
        #ip 协议
        self.cache += message
        if dic_net['标志'] == 5: #More Fragment
            i = dic_net['片偏移']*8//dic_net['总长度']
            msg = '\nreceiving packet slice %d...\n'%(i)
            append_message(msg)
            return 0,b'',''
        message = self.cache #已集齐
        append_message('\n切片集齐\n')
        self.cache = b'' #清空缓存

        s_ip = dic_net['源地址']
    #传输层
        message,dic_trans = decode_trans_message(message)
        return 1,message,s_ip

class Router:
    def __init__(self,tag_id,canvas):
        global MAC
        self.macs = [MAC,MAC+1,MAC+2];MAC+=3
        self.ips = ['0.0.0.0','0.0.0.0','0.0.0.0']
        # self.belong_nets = None  #NetCloud tuple, each net for each ip
        self.router_table = {}
        self.mac_cache = {}

        #网络层
        self.wait_queue = [] #ip_packet,  get one, send one


        self.canvas=canvas
        self.tag_id = tag_id
        self._width = 40
        self._height = 40
        self.x = 0 #image place, left top,left top,left top as origin
        self.y = 0
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_router)
        global item_to_instance_dic
        item_to_instance_dic[self.id]=self

    def move_to(self,pos): # pos: (x,y), origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))
        self.x,self.y = pos[0]+self._width/2,des_y+self._height/2

    def read(self,port):
        with open('tmp/bitstream','rb') as file:
        # 物理层
            START = file.read(5)
            if START!=b'START':
                print('error')
            d_mac_bys = file.read(6)
            d_mac = int.from_bytes(d_mac_bys,byteorder='little')
            if d_mac!= B_MAC and d_mac!=self.macs[port]:
                return 0  #不是自己的消息，退出
            else:
                frame = d_mac_bys+file.read()
        # 数据链路层
            ip_packet,dic_fra = decode_frame(frame)
            s_mac = dic_fra['s_mac']

            self.wait_queue.append(ip_packet)

            # routing
            msg = 'Router%d get the packet\n'%(self.tag_id)
            # append_message(msg)
            self.routing(s_mac)
            return 1

    def routing(self,s_mac):
    #网络层
        ip_packet = self.wait_queue[0]
        self.wait_queue = self.wait_queue[1:]

        message, dic_net =decode_IP_segment(ip_packet)
        d_ip = dic_net['目的地址']
        s_ip = dic_net['源地址']
        protocol = dic_net['协议']
        if protocol==255:
            ARP_message = message.decode('utf-8')
            #解析ARP
            req, src_ip, src_mac, req_ip = ARP_message.split('|')
            self.mac_cache[src_ip] = macstr_to_int(src_mac) #更新mac缓存

            if req=='req' and req_ip in self.ips: #返回一个ARP响应
                port = self.ips.index(req_ip)
                ARP(self.ips[port], self.macs[port], src_ip, req='rsp')
            return 
        # if s_mac==2:
        #     print(dic_net)
        self_net_ip_list = [extract_net_ip(ip) for ip in self.ips]
        d_net_ip = extract_net_ip(d_ip)
        if d_net_ip in self_net_ip_list:    # 在同一个网络，直接发射
            port = self_net_ip_list.index(d_net_ip)
            msg = '\nRouter%d resend the packet to port%d\n'%(self.tag_id,port)
            next_ip = d_ip
        else:                               # 在不同网络，查找路由表
            if self.router_table.get(d_ip)==None:
                next_ip,port = self.router_table['default']
            else:
                next_ip,port = self.router_table[d_ip]
            msg = '\nRouter%d resend the packet to host:%s\n'%(self.tag_id,next_ip)
        # search cache for mac or use ARP
        while(1):
            if self.mac_cache.get(next_ip)==None:
                # print('error,host can\'t find mac')
                #ARP
                ARP(self.ips[port], self.macs[port], next_ip)
            else:
                d_mac = self.mac_cache[next_ip]
                break
        # append_message(msg)
    # 数据链路层
            # 改变 src 和 des mac
        frame = encode_frame(d_mac,self.macs[port],ip_packet)
    # 物理层
        bitstream = b'START'+frame
        __d_net_ip = extract_net_ip(next_ip)
        transmit(bitstream, __d_net_ip)

class NetCloud:
    def __init__(self,tag_id,canvas):
        global MAC
        self.net_ip = '0.0.0.0'
        self.child_hosts = []
        self.child_routers = []

        self.canvas=canvas
        self.tag_id = tag_id
        self._width = 48
        self._height = 48
        self.x = 0 #image place, left top,left top,left top as origin
        self.y = 0
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_net)
        global item_to_instance_dic
        item_to_instance_dic[self.id]=self

    def move_to(self,pos): # pos: (x,y), origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))
        self.x,self.y = pos[0]+self._width/2,des_y+self._height/2

def draw_border():
    L = [canvas_l,canvas_r,canvas_b]
    for canvas in L:
        # print(canvas.winfo_height())
        canvas.create_rectangle(0+2,0+2,canvas.winfo_width()-2,canvas.winfo_height()-2,width=10)

################
## create window
################
window=tk.Tk()
window.title('PyNet-beta')
window.resizable(0,0)
window.wm_attributes('-topmost',0)
# window.wm_attributes('-topmost',1)
scale = 0.65
WWidth = int(1600*scale)
WHeight = int(1000*scale)
window.geometry(str(WWidth)+'x'+str(WHeight))

# flat, groove, raised, ridge, solid, or sunken
item_to_instance_dic = {}
old_label = 0
def mac_to_str(mac):
    return '.'.join([hex(e)[2:] for e in int.to_bytes(mac,6,'big')])
def macstr_to_int(mac_str):
    L = mac_str.split('.')
    s = 0
    a = 1
    for e in L[-1::-1]: #倒序
        s += a*int('0x'+e,16)
        a *= 255
    return int(s)

def show(event):
    global old_label
    item = canvas_l.find_withtag('current')
    if len(item)!=0:
        instance = item_to_instance_dic[item[0]]
        if instance.__class__.__name__=='Host':
            text = 'host:\n'+\
                   'mac: %s\n'%(mac_to_str(instance.mac))+\
                   'ip : %s\n'%(instance.ip)
        elif instance.__class__.__name__=='Router':
            text = 'router:\n'+\
                   'mac0: %s\n'%(mac_to_str(instance.macs[0]))+\
                   'mac1: %s\n'%(mac_to_str(instance.macs[1]))+\
                   'mac2: %s\n'%(mac_to_str(instance.macs[2]))+\
                   'ip0 : %s\n'%(instance.ips[0])+\
                   'ip1 : %s\n'%(instance.ips[1])+\
                   'ip2 : %s\n'%(instance.ips[2])
        elif instance.__class__.__name__=='NetCloud':
            text = 'net:\n'+\
                   'net_ip : %s\n'%(instance.net_ip)
        else:
            return 0

        if old_label!=0:
            old_label.destroy()
        la = tk.Label(window,text=text)
        la.place(relx=0.01,rely=0.02,relwidth=0.12)
        old_label = la

def init_text_message():
    text_message.delete('1.0', 'end')
    text_message.insert('end','Message>>')

def show_curr_host():  
    msg = '\ncurrent host:\n'+\
          '\tmac: %x\n'%(curr_host.mac)+\
          '\tip : %s\n'%(curr_host.ip)
    append_message(msg)

def change_host(event):
    global old_label
    global curr_host
    item = canvas_l.find_withtag('current')
    if len(item)!=0:
        instance = item_to_instance_dic[item[0]]
        if instance.__class__.__name__=='Host':
            curr_host = instance
            init_text_message()
            show_curr_host()

def change_des_host(event):
    item = canvas_l.find_withtag('current')
    if len(item)!=0:
        instance = item_to_instance_dic[item[0]]
        if instance.__class__.__name__=='Host':
            url = en_url.get()
            L = url.split('/')
            L[2]=instance.ip
            url_c = '/'.join(L)
            en_url.delete(0,'end')
            en_url.insert(0,url_c)

canvas_l=tk.Canvas(window)
canvas_r=tk.Canvas(window)
canvas_b=tk.Canvas(window)
canvas_l.place(relx=0,rely=0,relwidth=0.5,relheight=0.8)
canvas_r.place(relx=0.5,rely=0,relwidth=0.5,relheight=1)
canvas_b.place(relx=0,rely=0.8,relwidth=0.5,relheight=0.2)
canvas_l.bind("<Button-1>",show)
canvas_l.bind("<Double-Button-1>",change_host)
canvas_l.bind("<Button-3>",change_des_host)


window.update()
draw_border()
## window ok ###

################
## create img
################
# img_router = tk.PhotoImage(file='img/router.gif')
# img_net = tk.PhotoImage(file='img/net.gif')
# img_host = tk.PhotoImage(file='img/host.gif')

img = Image.open('img/router.png')
img_router = ImageTk.PhotoImage(img)
img = Image.open('img/net.png')
img_net = ImageTk.PhotoImage(img)
img = Image.open('img/host.png')
img_host = ImageTk.PhotoImage(img)

host_place=[(20,410),(85,580),(520,90),(650,300),(300,770),(740,500)]
net_place=[(170,440),(340,185),(490,360),(370,635),(590,600)]
router_place=[(340,350),(480,500)]

host_list = []
router_list = []
net_list = []
for i,place in enumerate(host_place):
    host = Host(i,canvas_l)
    host.move_to((scale*place[0],scale*(800-place[1])))
    host_list.append(host)
for i,place in enumerate(router_place):
    router = Router(i,canvas_l)
    router.move_to((scale*place[0],scale*(800-place[1])))
    router_list.append(router)
for i,place in enumerate(net_place):
    net = NetCloud(i,canvas_l)
    net.move_to((scale*place[0],scale*(800-place[1])))
    net_list.append(net)
window.update()
## image ok ####


################
## configure net
################
net_list[0].child_hosts=[0,1]
net_list[0].child_routers=[(0,1)] # R0 port 1
net_list[0].net_ip = '192.168.0.0'
host_list[0].ip = '192.168.0.2'
host_list[1].ip = '192.168.0.7'
router_list[0].ips[1] = '192.168.0.1'

net_list[1].child_hosts=[2]
net_list[1].child_routers=[(0,0)]
net_list[1].net_ip = '192.168.1.0'
host_list[2].ip = '192.168.1.3'
router_list[0].ips[0] = '192.168.1.1'

net_list[2].child_hosts=[3]
net_list[2].child_routers=[(0,2),(1,0)]
net_list[2].net_ip = '192.168.2.0'
host_list[3].ip = '192.168.2.3'
router_list[0].ips[2] = '192.168.2.1'
router_list[1].ips[0] = '192.168.2.2'

net_list[3].child_hosts=[4]
net_list[3].child_routers=[(1,1)]
net_list[3].net_ip = '192.168.3.0'
host_list[4].ip = '192.168.3.2'
router_list[1].ips[1] = '192.168.3.1'

net_list[4].child_hosts=[5]
net_list[4].child_routers=[(1,2)]
net_list[4].net_ip = '192.168.4.0'
host_list[5].ip = '192.168.4.2'
router_list[1].ips[2] = '192.168.4.4'

#### router table && mac cache 
host_list[0].router_table['default']='192.168.0.1'
host_list[1].router_table['default']='192.168.0.1'
host_list[2].router_table['default']='192.168.1.1'
host_list[3].router_table['default']='192.168.2.1'
# host_list[0].mac_cache['192.168.0.1'] = router_list[0].macs[1]
# host_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
# host_list[1].mac_cache['192.168.0.1'] = router_list[0].macs[1]
# host_list[1].mac_cache['192.168.0.2'] = host_list[0].mac
# host_list[2].mac_cache['192.168.1.1'] = router_list[0].macs[0]
# host_list[3].mac_cache['192.168.2.1'] = router_list[0].macs[2]
host_list[4].router_table['default']='192.168.3.1'
host_list[5].router_table['default']='192.168.4.4'
# host_list[4].mac_cache['192.168.3.1'] = router_list[1].macs[1]
# host_list[5].mac_cache['192.168.4.4'] = router_list[1].macs[2]


router_list[0].router_table['default']='192.168.2.2',2
# router_list[0].mac_cache['192.168.2.2'] = router_list[1].macs[0]
# router_list[0].mac_cache['192.168.0.2'] = host_list[0].mac
# router_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
# router_list[0].mac_cache['192.168.1.3'] = host_list[2].mac
# router_list[0].mac_cache['192.168.2.3'] = host_list[3].mac

router_list[1].router_table['default']='192.168.2.1',0
# router_list[1].mac_cache['192.168.2.1'] = router_list[0].macs[2]
# router_list[1].mac_cache['192.168.2.3'] = host_list[3].mac
# router_list[1].mac_cache['192.168.3.2'] = host_list[4].mac
# router_list[1].mac_cache['192.168.4.2'] = host_list[5].mac

window.update()
## net ok ###
################
## Draw lines
################
def put_bottom(cv,tag_id):
    tags = cv.find_below(tag_id)
    while len(tags)!=0:
        cv.tag_lower(tag_id,tags)
        tags = cv.find_below(tag_id)
# print(len(net_list))
for net in net_list:
    for host_tag_id in net.child_hosts:
        line = canvas_l.create_line(net.x,net.y,
                host_list[host_tag_id].x,
                host_list[host_tag_id].y,width = 3)
        put_bottom(canvas_l,line)
    # print(net.child_routers)
    for router_tag_id,_ in net.child_routers:
        line = canvas_l.create_line(net.x,net.y,
                router_list[router_tag_id].x,
                router_list[router_tag_id].y,width = 3)
        put_bottom(canvas_l,line)


################
## Send
################
def append_message(s):
    text_message.insert('end',s)

def Send():
    init_text_message()
    url = en_url.get()
    curr_host.request(url)

# current host
curr_host = host_list[0];

en_url = tk.Entry(window)
btn_send = tk.Button(window,text="Go!",command= Send)
# text_message = tk.Text(window, height=10)

from tkinter.scrolledtext import ScrolledText
text_message = ScrolledText(window,font=("隶书",18))

en_url.place(relx=0.05, rely=0.8+0.05, relwidth=0.2, relheight=0.05)
btn_send.place(relx=0.3+0.05, rely=0.8+0.05, relwidth=0.05,relheight=0.05)
text_message.place(relx=0.5+0.005, rely=0+0.008, relwidth=0.5-0.01,relheight=1-0.015)

init_text_message()
show_curr_host()

#for debug
en_url.insert('end','https://192.168.1.3/text.txt')

window.update()
# widget ok

window.mainloop()

