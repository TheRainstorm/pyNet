## 对多进程的共享数据变量以及信号量进行测试

from multiprocessing import Process, Semaphore; 
import multiprocessing as mp;
def func(temp):
    temp.value = temp.value + 1;
    print(temp.value);

sem = Semaphore(1);
temp = mp.Value("i", 0);
if __name__ == '__main__':
    for i in range(1):
        p = Process(target = func, args = (temp,));
        p.start();
        if(p == 0):
            p = Process(target = func, args = (temp,));
            p.start();
    for i in range (1):
        p.join();
    print(temp.value);