# 计算机网络project
---

## 说明
使用python模拟了两台主机通过**TCP/IP(融合了OSI的数据链路层和物理层，共五层)**协议进行通信的过程. 并使用tkinter库, 可视化了网络结构.  最后参照wireshark软件, 展示每一层的数据单元并格式化展示.

## 原理
### 网络体系结构
- 应用层
- 运输层(未实现)
- 网络层
- 数据链路层
- 物理层

### 实现
1. 数据从上往下到达物理层后，以二进制方式写入一个文件作为**物理媒介**
2. 实现广播：遍历一个网络内的所有主机及路由器，令其读取文件
3. 模拟过程本质上为若干个嵌套的函数调用

## 效果
![show](https://gitee.com/yuanfuyan/pyNet/raw/master/img/Snipaste_2019-12-08_16-32-12.png)

## TODO
- 将代码前端后端逻辑分离

- 添加校验序列, 模拟网络出错

- 网络结构可以编辑

- 使用多进程替代目前的嵌套函数调用方案

- 实现TCP的可靠传输机制

- 实现TCP的拥塞控制

## requirements
python 3.x

matplotlib (pip install matplotlib)
Pillow (pip install Pillow)

## 参考
- Tkinter 参考[http://effbot.org/tkinterbook/tkinter-index.htm](http://effbot.org/tkinterbook/tkinter-index.htm)

