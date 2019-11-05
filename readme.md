# 计算机网络project
---

## 说明
使用python封装**TCP/IP(融合了OSI的数据链路层和物理层，共五层)**协议，并使用tkinter可视化网络结构以及协议**同步**过程

## 原理
### 网络体系结构
- 应用层
- 运输层
- 网络层
- 数据链路层
- 物理层

### 实现
1. 数据从上往下到达物理层后，以二进制方式写入一个文件作为**物理媒介**
2. 实现广播：遍历一个网络内的所有主机及路由器，另其读取文件

## 效果
![show](https://gitee.com/yuanfuyan/pyNet/raw/master/img/Snipaste_2019-11-05_20-36-56.png)