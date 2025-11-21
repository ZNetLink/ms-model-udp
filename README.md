# ms-model-udp

智网妙算基础 UDP 模型

## 简介
基础 UDP 传输层模型，用于在妙算仿真中提供面向无连接的传输服务。  
模型按照标准 UDP 行为工作，负责：

- 接收上层应用的数据包，封装为 UDP 报文并交给 IP 模型发送；
- 从 IP 模型接收 UDP 报文，按照端口分发给对应的应用模块；
- 在仿真开始时，将自身的协议号（17）注册到所在节点的 IP 模型中。

> 本模型需要与 IP 模型配合使用，IP 模型需支持协议注册接口。

## 模型参数

当前 UDP 模型在 `models/udp.pr.m` 中定义，且未声明可配置属性；  
所有行为由端口监听、上层 ICI 字段和 IP 层交互共同决定，用户无需单独配置模型参数。

## 模型行为概述

### 初始化与协议注册

- UDP 进程在仿真开始时（`Wait -> Init`）查找所在节点上的 IP 模型实例；
- 成功找到 IP 模型后，在 `Init` 退出阶段中确定与 IP 模型的收发流（`stream_to_ip` / `stream_from_ip`）；
- 通过 `miaosuan_models_basic.ip.register_protocol` 接口，将协议号 `17`（UDP）注册到 IP 模型，之后 IP 能够将 UDP 报文转发给本进程。

### Socket 与端口管理

UDP 不维护连接状态，仅基于端口进行收发。  
应用通过远程中断 ICI `udp_command` 控制端口：

- `listen` 命令  
  - 在指定或自动分配的本地端口上创建一个 UDP “socket”；  
  - 绑定该端口与应用模块之间的输入/输出流，用于后续数据转发。
- `close` 命令  
  - 关闭指定本地端口上的 UDP “socket”，释放绑定关系。

内部结构 `UdpSocket` 记录：

- `local_port`：本地 UDP 端口；  
- `stream_to_app` / `stream_from_app`：与应用模块的收发流索引；  
- `app_module`：对应的应用模块对象。

### 应用 → UDP → IP 方向

当应用通过与 UDP 相连的流发送数据包时：

1. 应用需同时附带 ICI，其中至少包含：  
   - `remote address`：目标 IP 地址；  
   - `remote port`：目标 UDP 端口；  
   - `local port`：本地端口（可选，缺省时由 UDP 分配动态端口）。
2. UDP 根据 ICI 信息构造 `udp_dgram` 格式的数据包：  
   - 在 `header` 字段中存放 `UdpHeader`（源端口、目的端口、长度、校验和）；  
   - 在 `data` 字段中嵌入原始应用数据包。
3. UDP 创建 IP 层 ICI `ip_ind`，设置：  
   - `dest address`：目标 IP 地址；  
   - `protocol`：`17`（UDP）。  
4. 通过与 IP 模型的输出流，发送构造好的 UDP 报文。

### IP → UDP → 应用 方向

当 IP 模型将 UDP 报文上交给本进程时：

1. UDP 从 IP 附带的 ICI 中读取：  
   - `src address`：源 IP 地址；  
   - `in intf idx`：入方向接口索引（用于透传给应用）。  
2. 检查数据包格式是否为 `udp_dgram`，并从 `header` 字段中解析：  
   - 源端口 `SrcPort` 和目的端口 `DstPort`；  
3. 根据目的端口在内部 `sockets` 表中查找对应监听的应用：  
   - 若找不到匹配端口，则丢弃该 UDP 报文；  
   - 若找到，将 `data` 字段中的有效负载包转发给应用。
4. 在转发给应用时，UDP 创建 ICI `udp_ind`，填充：  
   - `remote address` / `remote port`：对端地址与端口；  
   - `local port`：接收端本地端口；  
   - `in intf idx`：入接口索引。

## 数据包格式（`models/udp_dgram.pkt.m`）

UDP 使用的数据包格式在 `models/udp_dgram.pkt.m` 中定义，主要字段如下：

- `header`（类型：`type = 6`，指针，对应 Python 中的 `UdpHeader`）  
  - `SrcPort`：源 UDP 端口（整型）；  
  - `DstPort`：目的 UDP 端口（整型）；  
  - `Length`：UDP 报文总长度（字节），含头部和数据；  
  - `Checksum`：校验和，目前实现为占位字段。
- `data`（类型：`type = 5`，数据包）  
  - 承载上层应用传入的业务数据包。

## ICI 字段说明

### 应用控制 ICI：`models/udp_command.ici.m`

用于应用模块通过远程中断控制 UDP 端口监听/关闭：

- `command`（类型：`type = 1`，字符串）  
  - 取值：`"listen"` 或 `"close"`。
- `local port`（类型：`type = 2`，整型）  
  - `listen` 时：期望监听的本地端口，`<= 0` 则自动分配动态端口；  
  - `close` 时：要关闭的本地端口。
- `app module id`（类型：`type = 2`，整型）  
  - 发起命令的应用模块的仿真对象 ID。

### UDP 上行指示 ICI：`models/udp_ind.ici.m`

UDP 将收到的数据包上交应用时使用：

- `local address`（类型：`type = 2`，整型）  
  - 本端 IP 地址（由 IP 层传入或由上层使用时填充）。  
- `local port`（类型：`type = 2`，整型）  
  - 本地 UDP 端口（应用监听的端口）。  
- `remote address`（类型：`type = 2`，整型）  
  - 远端 IP 地址。  
- `remote port`（类型：`type = 2`，整型）  
  - 远端 UDP 端口。  
- `in intf idx`（类型：`type = 2`，整型）  
  - 入方向接口索引，由 IP 层 ICI 中的同名字段传递而来。

## 统计指标

UDP 模型内部注册了若干统计量（桶式统计，`SUM_PER_TIME` 聚合），名称格式如下：

- `udp.<plt_name>.<device_name>.recv_bps`：设备接收 UDP 业务数据速率（比特每秒）；  
- `udp.<plt_name>.<device_name>.sent_bps`：设备发送 UDP 业务数据速率（比特每秒）；  
- `udp.<plt_name>.<device_name>.recv_pps`：设备接收 UDP 报文速率（包每秒）；  
- `udp.<plt_name>.<device_name>.send_pps`：设备发送 UDP 报文速率（包每秒）。

通过妙算统计接口可进一步查询这些指标，用于评估节点 UDP 业务负载情况。
