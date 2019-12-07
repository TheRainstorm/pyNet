from tkinter import *
from PIL import Image, ImageTk

from skimage import io
import matplotlib.pyplot as plt
import time
import random
import os
import base64

from code_and_decode import *
from util import *

def mainWindow():
    window=Tk()
    window.title('PyNet-alpha')
    window.resizable(0,0)
    window.wm_attributes('-topmost',0)
    # window.wm_attributes('-topmost',1)
    scale = 0.65
    WWidth = int(1600*scale)
    WHeight = int(1000*scale)
    window.geometry(str(WWidth)+'x'+str(WHeight))

    return window

class ToolBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.place(relx=0, rely=0, relwidth=1, relheight=0.05)

        self.btn1 = Button(self, text="Broswer", relief=GROOVE, command=self.changeTo1)
        self.btn1.place(relx=0, rely=0, relwidth=0.1, relheight=1)
        self.btn2 = Button(self, text="Network", relief=GROOVE, command=self.changeTo2)
        self.btn2.place(relx=0.1, rely=0, relwidth=0.1, relheight=1)
        self.btn3 = Button(self, text="WireShark", relief=GROOVE, command=self.changeTo3)
        self.btn3.place(relx=0.2, rely=0, relwidth=0.1, relheight=1)

    def changeTo1(self):
        broswer.lift() #broswer为全局变量

    def changeTo2(self):
        network.lift()

    def changeTo3(self):
        wireshark.lift()

class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)

        self.label = Label(self, bd=1, relief=SUNKEN, anchor=CENTER)
        self.label.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.label.update_idletasks()
        self.place(relx=0, rely=0.9525, relwidth=1, relheight=0.045)

    def set(self, text):
        self.label.config(text=text)
        self.label.update_idletasks()

class Broswer(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.place(relx= 0, rely=0.05, relwidth=1, relheight=0.9)

        div = Frame(self)
        div.place(relx=0.5, rely=0.5, anchor=CENTER)

        img = Image.open('img/black.png')
        photo = ImageTk.PhotoImage(img)
        logo = Label(div, image=photo)
        logo.photo = photo #去掉会显示不出图片, 因为图片是局部变量, 没有保存索引就被释放掉了
        logo.grid(columnspan=3, sticky=W+E+N+S)

        label = Label(div, text="url")
        label.grid()

        url = Entry(div)
        url.grid(row=1, column=1, sticky=W+E)

        go = Button(div, bg='pink', text='GO!', command=Send, height=1, width=3)
        go.grid(row=1, column=2)
        
        self.url = url
        self.go = go

def WireShark(master):
    wireshark = Frame(window, bg='blue')
    wireshark.place(relx= 0, rely=0.05, relwidth=1, relheight=0.9)
    return wireshark

class DrawObj:
    def __init__(self, canvas):
        self.canvas=canvas
        self._width = 0
        self._height = 0
        self.x = 0
        self.y = 0
        self.item = -1
    
    def move_to(self, pos): # pos 为中心位置
        d_x, d_y = pos[0]-self._width/2, pos[1]-self._height/2
        self.canvas.coords(self.item, (d_x, d_y))
        self.x, self.y = pos[0], pos[1]

        global item_to_instance_dic #每一个都调用过move_to
        item_to_instance_dic[self.item]=self
    
class Host_(DrawObj):
    def __init__(self, canvas):
        DrawObj.__init__(self, canvas)
        global img_host
        self._width = 48
        self._height = 48
        self.item = canvas.create_image(0, 0, anchor='nw', image=img_host)

class Router_(DrawObj):
    def __init__(self, canvas):
        DrawObj.__init__(self, canvas)
        global img_router
        self._width = 40
        self._height = 40
        self.item = canvas.create_image(0, 0, anchor='nw', image=img_router)

class Net_(DrawObj):
    def __init__(self, canvas):
        DrawObj.__init__(self, canvas)
        global img_net
        self._width = 48
        self._height = 48
        self.item = canvas.create_image(0, 0, anchor='nw', image=img_net)
#------------------------BACK END--------------------------
MAC=0 #每次自增1，确保每台机器mac不同
B_MAC=2**48-1 #broadcast mac
LEN = 1000

def Send():
    url = broswer.url.get()
    src_host.request(url)

def append_message(msg):
    print(msg)

def transmit(bitstream, __d_net_ip):
    net_id =int(__d_net_ip.split('.')[-2])
    # print(net_id)
    with open('tmp/bitstream','wb') as file:
        file.write(bitstream)

    def broadcast_to_net(net_id):
        for host_id in net_list[net_id].child_hosts:
            host_list[host_id].service()
        for router_id,port in net_list[net_id].child_routers:
            router_list[router_id].read(port)
    broadcast_to_net(net_id)

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

class Host(Host_):
    def __init__(self, id, canvas):
        Host_.__init__(self, canvas)
        global MAC
        self.mac = MAC;MAC+=1
        self.ip = '0.0.0.0'
        self.router_table = {} #路由表
        self.mac_cache = {} #mac 缓存

        self.cache = b'' # ip packet slice 解析后的运输层报文缓存
        self.id = id
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
class Router(Router_):
    def __init__(self, id, canvas):
        Router_.__init__(self, canvas)
        global MAC
        self.macs = [MAC,MAC+1,MAC+2];MAC+=3
        self.ips = ['0.0.0.0','0.0.0.0','0.0.0.0']
        self.router_table = {}
        self.mac_cache = {}

        #网络层
        self.wait_queue = [] #ip_packet,  get one, send one
        self.id = id
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
            msg = 'Router%d get the packet\n'%(self.id)
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
            msg = '\nRouter%d resend the packet to port%d\n'%(self.id,port)
            next_ip = d_ip
        else:                               # 在不同网络，查找路由表
            if self.router_table.get(d_ip)==None:
                next_ip,port = self.router_table['default']
            else:
                next_ip,port = self.router_table[d_ip]
            msg = '\nRouter%d resend the packet to host:%s\n'%(self.id,next_ip)
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

class Net(Net_):
    def __init__(self, id, canvas):
        Net_.__init__(self, canvas)
        self.net_ip = '0.0.0.0'
        self.child_hosts = []
        self.child_routers = []
        self.id = id

#------------------------BACK END--------------------------

# main
window = mainWindow()

# toolbar and status bar
toolbar = ToolBar(window)
statusbar = StatusBar(window)

# three tab (frame)
#-------------------broswer page---------------------------
broswer = Broswer(window)
broswer.url.insert('end','https://192.168.1.3/text.txt')
#-------------------network page---------------------------
network = Frame(window)
network.place(relx= 0, rely=0.05, relwidth=1, relheight=0.9)
height, width = window.winfo_height()*0.9, window.winfo_width()

item_to_instance_dic = {}
old_label = None


def drawRectangle():
    global src_host
def show(event):
    global old_label
    item = canvas.find_withtag(CURRENT)
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
        elif instance.__class__.__name__=='Net':
            text = 'net:\n'+\
                   'net_ip : %s\n'%(instance.net_ip)
        else:
            return 0

        if old_label!=None:
            old_label.destroy()
        la = Label(network,text=text)
        la.place(relx=0.01,rely=0.02,relwidth=0.12)
        old_label = la

def move_src_rect():
    global src_host, src_rect
    canvas.coords(src_rect, (src_host.x-src_host._width/2, src_host.y-src_host._height/2,
                            src_host.x+src_host._width/2, src_host.y+src_host._height/2))

def move_dst_rect():
    global dst_host, dst_rect
    canvas.coords(dst_rect, (dst_host.x-dst_host._width/2, dst_host.y-dst_host._height/2,
                            dst_host.x+dst_host._width/2, dst_host.y+dst_host._height/2))

def change_host(event):
    global src_host
    item = canvas.find_withtag('current')
    if len(item)!=0:
        instance = item_to_instance_dic[item[0]]
        if instance.__class__.__name__=='Host':
            src_host = instance
            statusbar.set('current host: %s\t\tdestination host: %s'%(src_host.ip,dst_host.ip))
            move_src_rect()
def change_des_host(event):
    global dst_host
    item = canvas.find_withtag('current')
    if len(item)!=0:
        instance = item_to_instance_dic[item[0]]
        if instance.__class__.__name__=='Host':
            url = broswer.url.get()
            L = url.split('/')
            L[2]=instance.ip
            url_c = '/'.join(L)
            broswer.url.delete(0,'end')
            broswer.url.insert(0,url_c)

            dst_host = instance
            statusbar.set('current host: %s\t\tdestination host: %s'%(src_host.ip,dst_host.ip))
            move_dst_rect()

canvas = Canvas(network)
canvas.place(relwidth=1, relheight=1)
canvas.bind("<Button-1>",show)
canvas.bind("<Double-Button-1>",change_host)
canvas.bind("<Button-3>",change_des_host)

host_place=[(0.0625, 0.46875), (0.140625, 0.6875), (0.65, 0.0625), (0.859375, 0.3125), (0.4, 0.9), (0.884375, 0.578125)]
net_place=[(0.25, 0.5), (0.46875, 0.1796875), (0.65625, 0.3984375), (0.5, 0.75), (0.7, 0.703125)]
router_place=[(0.36875, 0.390625), (0.525, 0.55)]

# list
host_list=[]
router_list=[]
net_list=[]
img = Image.open('img/router.png')
img_router = ImageTk.PhotoImage(img)
img = Image.open('img/net.png')
img_net = ImageTk.PhotoImage(img)
img = Image.open('img/host.png')
img_host = ImageTk.PhotoImage(img)
# draw and append list
for i, place in enumerate(host_place):
    host = Host(i, canvas)
    host.move_to((place[0]*width, place[1]*height))
    host_list.append(host)
for i, place in enumerate(net_place):
    net = Net(i, canvas)
    net.move_to((place[0]*width, place[1]*height))
    net_list.append(net)
for i, place in enumerate(router_place):
    router = Router(i, canvas)
    router.move_to((place[0]*width, place[1]*height))
    router_list.append(router)

# configure net
configure_net(net_list, host_list, router_list)

# draw line
for net in net_list:
    for host_id in net.child_hosts:
        line = canvas.create_line(net.x,net.y,
                host_list[host_id].x,
                host_list[host_id].y,width = 3)
        put_bottom(canvas,line)
    for router_id,_ in net.child_routers:
        line = canvas.create_line(net.x,net.y,
                router_list[router_id].x,
                router_list[router_id].y,width = 3)
        put_bottom(canvas,line)

src_host = host_list[0]
dst_host = host_list[2]
statusbar.set('current host: %s\t\tdestination host: %s'%(src_host.ip,dst_host.ip))

src_rect = canvas.create_rectangle((src_host.x-src_host._width/2, src_host.y-src_host._height/2),
                                    (src_host.x+src_host._width/2, src_host.y+src_host._height/2),
                                    width=3, outline='green')
dst_rect = canvas.create_rectangle((dst_host.x-dst_host._width/2, dst_host.y-dst_host._height/2),
                                    (dst_host.x+dst_host._width/2, dst_host.y+dst_host._height/2),
                                    width=3, outline='red')
#----------------------------------------------------------


wireshark = WireShark(window)
toolbar.btn2.invoke() #default tab


if __name__=="__main__":
    window.mainloop()