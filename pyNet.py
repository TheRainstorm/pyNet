import tkinter as tk
from PIL import Image, ImageTk
import time
import random

MAC=0 #每次自增1，确保每台机器mac不同

def extract_net_ip(ip, mask=None):
    L = ip.split('.')
    L[3]='0'
    return '.'.join(L)

def transmit(bitstream, __d_net_ip):
    net_tag_id =int(__d_net_ip.split('.')[-2])
    # print(net_tag_id)
    with open('bitstream','wb') as file:
        file.write(bitstream)

    def broadcast_to_net(net_tag_id):
        for host_tag_id in net_list[net_tag_id].child_hosts:
            host_list[host_tag_id].read()
        for router_tag_id,port in net_list[net_tag_id].child_routers:
            router_list[router_tag_id].read(port)
    broadcast_to_net(net_tag_id)

# class router_table:
#     def __init__(self):
#         self.data={}

class Host:
    def __init__(self,tag_id,canvas):
        global MAC
        self.mac = MAC;MAC+=1
        self.ip = '0.0.0.0'
        self.router_table = {}
        self.mac_cache = {}

        self.canvas=canvas
        self.tag_id = tag_id
        self._width = 35
        self._height = 60
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_host)

    def move_to(self,pos): # origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))

    def read(self):
        with open('bitstream','rb') as file:
        # 物理层
            START = file.read(5)
            if START!=b'START':
                print('error')
        # 数据链路层
            d_mac = int.from_bytes(file.read(6),byteorder='little')
            if d_mac == self.mac:
            #网络层
                ip_packet = file.read().decode('utf-8')
                # print(ip_packet.decode('utf-8'))
                ip_header = ip_packet.split(':')[:5]
                s_ip = ip_header[4]

            #应用层
                le = len('tcp_header,')
                s = ip_packet.split(':')[5][le:le+3]
                if s=='Req':
                    msg = '\nhost: %s get request from host: %s'%(self.ip,s_ip)
                    append_message(msg)
                    self.response(s_ip)
                    # print('yes')
                elif s=='Res':
                    msg = '\nhost: %s get response from host: %s'%(self.ip,s_ip)
                    append_message(msg)
                else:
                    print('bad')
                # self.response(s_ip)

    def request(self,url):
    # 应用层
        protocal,_,d_ip,file = url.split('/')
        protocal = protocal[:-1]
        Accept=file.split('.')[1]
        Ip = self.ip

        message = 'Request\n'+\
              'URL:\t\t%s\n'%url+\
              '方法:\t\tGET\n'+\
              '协议:\t\t%s\n'%(protocal)+\
              'Accept:\t\t%s\n'%(Accept)+\
              'Host:\t\t%s\n'%(d_ip)+\
              'From:\t\t%s\n'%(Ip)

        msg = '\n应用层报文:\n'+message
        append_message(msg)

        # message = 'header,body' #char
        self.send(d_ip,message)

    def response(self,ip):
        # 应用层
        Ip = self.ip

        message = 'Response\n'+\
              '状态码:\t\t%s\n'%('200 OK')+\
              'To:\t\t%s\n'%(ip)+\
              'From:\t\t%s\n'%(Ip)

        msg = '\n应用层报文:\n'+message
        append_message(msg)

        # message = 'header,body' #char
        self.send(ip,message)

    def send(self,d_ip,message):
    # 运输层
        message = 'tcp_header,'+message

        msg = '\n运输层 datagram:\n%s\n'%(message)
        append_message(msg)
    # 网络层
        ip_packet = 'ip_header:d_ip:'+d_ip+':s_ip:'+self.ip+':'+message
        msg = '\n网络层 packet:\n%s\n'%(ip_packet)
        append_message(msg)

        # get d_ip from ip_header (we already have)
        d_net_ip = extract_net_ip(d_ip)
        if d_net_ip==extract_net_ip(self.ip):
            next_ip = d_ip #直接发射
        else: # 查找路由表
            # print(self.router_table)
            # print(d_net_ip)
            if self.router_table.get(d_net_ip)==None:
                next_ip = self.router_table['default']
            else:
                next_ip = self.router_table[d_net_ip]
        # search cache for mac or use ARP
        if self.mac_cache.get(next_ip)==None:
            print('error,host can\'t find mac')
        else:
            d_mac = self.mac_cache[next_ip]
        # d_mac = 1 # assume we get the mac
    # 数据链路层
        frame = encode_mac(d_mac)+ip_packet.encode('utf-8') #已为二进制
        msg = '\n数据链路层 frame:\n%s\n'%(frame)
        append_message(msg)
    # 物理层
        bitstream = b'START'+frame+b'END'
        # put the bitstream on the bus
        msg = '\n物理层 bitstream:\n%s\n'%(bitstream)
        append_message(msg)

        __d_net_ip = extract_net_ip(next_ip) #can't see
        transmit(bitstream, __d_net_ip)


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
        self._width = 48
        self._height = 48
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_router)

    def move_to(self,pos): # origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))

    def read(self,port):
        with open('bitstream','rb') as file:
            # 物理层
            START = file.read(5)
            if START!=b'START':
                print('error')
            # 数据链路层
            d_mac = int.from_bytes(file.read(6),byteorder='little')
            if d_mac == self.macs[port]:
                # 网络层
                ip_packet = file.read()
                # print(ip_packet.decode('utf-8'))
                self.wait_queue.append(ip_packet)
                # 转发
                msg = 'Router%d get the packet\n'%(self.tag_id)
                append_message(msg)
                self.send()

    def send(self):
    # 网络层
        ip_packet = self.wait_queue[0].decode('utf-8')
        d_ip = ip_packet.split(':')[2]

        self_net_ip_list = [extract_net_ip(ip) for ip in self.ips]
        d_net_ip = extract_net_ip(d_ip)
        if d_net_ip in self_net_ip_list:    # 在同一个网络，直接发射
            msg = '\nRouter%d resend the packet to port%d\n'%(self.tag_id,port)
            port = self_net_ip_list.index(d_net_ip)
            next_ip = d_ip
        else:                               # 在不同网络，查找路由表
            if self.router_table.get(d_ip)==None:
                next_ip = self.router_table['default']
            else:
                next_ip = self.router_table[d_ip]
            msg = '\nRouter%d resend the packet to host:%s\n'%(self.tag_id,nex_ip)
            __d_net_ip = extract_net_ip(next_ip) #can't see
        # 查找mac cache
        # print(next_ip)
        if self.mac_cache.get(next_ip)==None:
            print('error,router %d can\'t find mac'%(self.tag_id))
        else:
            d_mac = self.mac_cache[next_ip]

        append_message(msg)
    # 数据链路层
            # 改变 source mac
        frame = encode_mac(d_mac)+ip_packet.encode('utf-8')
    # 物理层
        bitstream = b'START'+frame+b'END'
        __d_net_ip = extract_net_ip(next_ip)
        transmit(bitstream, __d_net_ip)



def encode_mac(mac):
    return int.to_bytes(mac,6,byteorder='little')

class NetCloud:
    def __init__(self,tag_id,canvas):
        global MAC
        self.net_ip = '0.0.0.0'
        self.child_hosts = []
        self.child_routers = []

        self.canvas=canvas
        self.tag_id = tag_id
        self._width = 100
        self._height = 60
        self.id=canvas.create_image(0, 0, anchor='nw', image=img_net)

    def move_to(self,pos): # origin in the left bottom
        des_y = self.canvas.winfo_height()-pos[1]-self._height
        self.canvas.coords(self.id,(pos[0],des_y))

def draw_border():
    L = [canvas_l,canvas_r,canvas_b]
    for canvas in L:
        # print(canvas.winfo_height())
        canvas.create_rectangle(0+2,0+2,canvas.winfo_width()-2,canvas.winfo_height()-2,width=10)

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
canvas_l=tk.Canvas(window)
canvas_r=tk.Canvas(window)
canvas_b=tk.Canvas(window)
canvas_l.place(relx=0,rely=0,relwidth=0.5,relheight=0.8)
canvas_r.place(relx=0.5,rely=0,relwidth=0.5,relheight=1)
canvas_b.place(relx=0,rely=0.8,relwidth=0.5,relheight=0.2)

window.update()
draw_border()
# Frame ok

################
## create img
################
img_router = tk.PhotoImage(file='img/router.gif')
img_net = tk.PhotoImage(file='img/net.gif')
img_host = tk.PhotoImage(file='img/host.gif')


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
host_list[0].mac_cache['192.168.0.1'] = router_list[0].macs[1]
host_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
host_list[1].mac_cache['192.168.0.1'] = router_list[0].macs[1]
host_list[1].mac_cache['192.168.0.2'] = host_list[0].mac
host_list[2].mac_cache['192.168.1.1'] = router_list[0].macs[0]
host_list[3].mac_cache['192.168.2.1'] = router_list[0].macs[2]
host_list[4].router_table['default']='192.168.3.1'
host_list[5].router_table['default']='192.168.4.4'
host_list[4].mac_cache['192.168.3.1'] = router_list[1].macs[1]
host_list[5].mac_cache['192.168.4.4'] = router_list[1].macs[2]


router_list[0].router_table['default']='192.168.2.2'
router_list[0].mac_cache['192.168.2.2'] = router_list[1].macs[0]
router_list[0].mac_cache['192.168.0.2'] = host_list[0].mac
router_list[0].mac_cache['192.168.0.7'] = host_list[1].mac
router_list[0].mac_cache['192.168.1.3'] = host_list[2].mac
router_list[0].mac_cache['192.168.2.3'] = host_list[3].mac

router_list[1].router_table['default']='192.168.2.1'
router_list[1].mac_cache['192.168.2.1'] = router_list[0].macs[2]
router_list[1].mac_cache['192.168.4.2'] = host_list[5].mac

window.update()

################
## Send
################
def append_message(s):
    text_message.insert('end',s)

def Send():
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
text_message.insert('end','Message>>')

#for debug
en_url.insert('end','https://192.168.0.7/test.txt')
msg = '\ncurrent host:\n'+\
      '\tmac: %x\n'%(curr_host.mac)+\
      '\tip : %s\n'%(curr_host.ip)
append_message(msg)

window.update()
# widget ok

window.mainloop()

