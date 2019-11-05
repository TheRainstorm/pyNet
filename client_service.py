import multiprocessing as mp;
from multiprocessing import Process, Semaphore;

def wait(msg):
    while(True):
        if msg <= 0:
            ;
        else
            msg = msg - 1;

def signal(msg):
    msg += 1;

def send_data():

def request():

def response():


# i 代表哪一个服务器做出反应;
def service(i):
    while(True):
        wait(msg.value);
        bus.acquire();
        # read file;
        # data
        if is_self():
            #解析请求类型: 如果为request
            if 'request':
                response(i);
                # response要注意分片
            else:
                # show in screen;
                # 要注意组装片数;
            bus.release();
        else:
            # 将读取的数据写回到总线上;
            signal(msg.value);

def client(i):
    # 一直循环, 等待捕获事件;
    if button:
        bus.acquire();
        # 封装至底层;
        request(i);
        signal(msg.value);
        bus.release();

if __name__ == '__main__':
    bus = Semaphore(1);
    msg = mp('i', 0);

    p_s_lst = [];
    p_c_lst = [];
    for i in range(10):
        p = Process(target=service, args = (i,));
        p_lst.append(p);
        p.start();

    for i in range(10):
        p = Process(target=client, args=(i,));
        p_c_lst.append(p);
        p.start();
    
    # 
    # [p.join() for p in p_s_lst];
    # [p.join() for p in p_c_lst];
