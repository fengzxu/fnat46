### 场景描述
在当前IPv4单栈局域网内，客户端（PC端、手机端）通过有线或无线方式访问外部IPv6单栈网络资源。

### 整体思路
![flow](https://github.com/fengzxu/fnat46/raw/master/images/flow.png "flow")
局域网内终端接入协议转换网关，通过DNS46完成域名解析，对访问IPv6资源的网络请求通过NAT46协议转换设备完成协议转换（请求、响应），以完成全程网络会话。

### 流程时序
![sequence](https://github.com/fengzxu/fnat46/raw/master/images/sequence.png "sequence")
1. IPv4客户端向域名服务器DNS46发起资源服务网络请求（A记录）；
2. DNS46通过递归查询公网该服务域名的A记录。如果得到A记录，则返回给客户端，客户端继续使用A记录的IPv4完成网络请求；
3. 如果DNS46查询到该域名只有AAAA记录，则表示该域名服务只提供了IPv6单栈服务，需要NAT46的转换服务；
4. DNS46从可用IPv4资源池中选择一个IP，注册该IPv4与服务域名IPv6的映射，将该映射同步至NAT46网关，然后将该IPv4返回给客户端；
5. 客户端向该 IPv4发起网络会话请求，该请求通过路由到达DNS46网关；
6. DNS46网关以报头目的IP查询映射，得到真实的IPv6目的地址，将IPv4协议报头替换为IPv6报头，通过NAT46网关的IPv6出口以IPv6协议向服务域名发起请求；
7. NAT46网关收到响应后，通过查询映射表，将IPv6报头转换为IPv4报头，返回给IPv4客户端，会话完成。

### NAT46网关
用于完成IPv4报头和IPv6报头的协议相互转换，内置映射表。协议转换参考IETF相应RFC文档。

### DNS46域名服务器
**（项目当前暂未实现）**
提供域名服务，做为所有客户端的第一级DNS服务器，通过DNS递归查询，对IPv4服务资源正常返回A记录，对IPv6服务资源返回临时A记录，与NAT46同步A记录与AAAA记录的映射。

### 实际应用需解决的问题
- 项目已通过功能性验证测试（ICMP/TCP/UDP)，但远未达到产品级可用标准；
- 虽然使用了DPDK框架，但协议包并未实现ZERO-COPY，直接复制了PAYLOAD，有望后面尝试解决；
- 三层协议转换要考虑到所有可能的协议类型（ARP/IP/GRE/VLAN/MPLS）等；
- 处理网络包的分段；

### 建立开发环境
1. 安装Intel NFF-GO DPDK平台框架 (https://github.com/intel-go/nff-go)
2. 开发机器至少3个网卡，其中1个管理口，1个IPv4网络接口，1个IPv6网络接口
3. IPv4&IPv6网络接口加载DPDK绑定
4. 根据网络环境更改编译文件和运行配置文件

### 联系本人
如对本项目或IPv4与IPv6协议转换、应用相关感兴趣，欢迎联系： xujf000@gmail.com 