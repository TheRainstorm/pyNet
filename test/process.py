from multiprocessing import Process
import os
def func():
    global n        #设置全局环境变量
    n = 0
    print('pid : %s' %os.getpid(),n)     #打印这里的pid与n的值
    print('hello')

if __name__ == "__main__":
    n = 100
    p = Process(target=func)           #注册子进程
    p.start()       #启动子进程
    p.join()       #感知子进程的结束
    print(n)        #打印父进程的n的值

#结果为：
#pid : 8940 0
#7488 100
#多进程之间如果不通过特殊的手段共享数据，那么多个进程之间的数据是完全隔离的