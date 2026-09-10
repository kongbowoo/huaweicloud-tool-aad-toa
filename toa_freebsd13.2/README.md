# TOA for FreeBSD 13.2

华为高防（AAD）TOA 模块的 FreeBSD 13.2 移植版，在服务端解析 TCP option（opcode 254）中携带的真实客户端 IP/Port，供 `getpeername()`/`getsockname()` 返回真实源地址。

## 与 Linux 版的实现差异

| Linux 版机制 | 本目录实现 |
|---|---|
| hook `tcp_v4_syn_recv_sock` 存 `sk_user_data` | pfil(9) 入站 IPv4 hook 解析 SYN，写入五元组 hash 表（TTL 300s，容量 65536） |
| hook `inet_getname`（kallsyms + 页表改写） | 替换 `tcp_usrreqs.pru_peeraddr`（内核可写数据，加载时保存原指针，卸载时恢复） |
| `/proc/net/toa_stats` | `sysctl net.inet.toa.*`（per-CPU counter） |
| `module_param saddr_scope`（分号分隔） | `sysctl net.inet.toa.scope` / loader tunable `toa.scope`（逗号分隔） |

## 编译安装

在 FreeBSD 13.2 机器上执行（需要安装 `/usr/src` 源码树）：

```shell
# 将 toa_freebsd13.2 目录拷到目标机后：
cd toa_freebsd13.2
make
make install    # 可选：安装到 /boot/modules
```

若 src 树不在 `/usr/src`，指定路径：

```shell
make SYSDIR=/path/to/freebsd-src/sys
```

## 加载与配置

```shell
# 加载
kldload ./toa.ko

# 配置回源地址网段（与 Linux 版 saddr_scope 等价；不配置则对所有 SYN 生效）
sysctl net.inet.toa.scope="10.0.0.0/8,192.168.1.0/24"

# 查看统计
sysctl net.inet.toa
```

开机自动加载（`/boot/loader.conf`）：

```ini
# loader.conf
toa_load="YES"
toa.scope="10.0.0.0/8"
```

## 验证

```shell
# 1. 加载后经高防回源建立连接
# 2. 在服务端用 python 验证 getpeername：
python3 -c "import socket; s=socket.socket(); s.connect(('<proxy_or_client>','<port>')); print(s.getpeername())"
# 3. 观察 syn_recv_sock_toa / getname_toa_ok 计数增长：
sysctl net.inet.toa.syn_recv_sock_toa net.inet.toa.getname_toa_ok
```

## 边界与注意事项

- 上游高防必须开启 TOA 回源；中间设备剥离 option 254 即失效（与 Linux 版一致）。
- syncookies 模式下 ACK 握手无 TOA option，对应连接返回代理地址（与 Linux 版行为一致）。
- SYN 重传会覆盖表项，幂等安全；表项 TTL 300 秒由 callout 每 60 秒回收。
- 仅支持 IPv4 与 IPv4-mapped-IPv6（v6 原生地址返回代理地址）；pfil hook 挂在 `inet_pfil_head`，VIMAGE 内核下默认 vnet 生效。
- 内核升级（13.2 -> 13.x/14）需重新编译；`pfil`/`pru_peeraddr` API 在 13.x 内稳定。
