# huaweicloud-tool-aad-toa

[English](README_EN.md) | 简体中文

华为云高防（[AAD](https://www.huaweicloud.com/product/aad.html)）专用 TOA（TCP Option Address）内核模块，基于淘宝开源 TOA 内核模块优化，用于在服务端解析真实客户端源 IP，可直接在 Linux / FreeBSD 服务器上编译安装。

## 工作原理

在高防（LVS FULLNAT）回源场景下，TCP 连接经代理转发后，服务器看到的源地址是代理地址。高防在回源 SYN 报文的 TCP option（opcode 254）中携带真实客户端 `{IP, Port}`，服务端加载本模块后：

1. 拦截 SYN 报文，解析 option 254 中的真实地址
2. 应用调用 `getpeername()` 时返回真实客户端 `{IP, Port}`

## 版本选择

| 目录 | 适用系统 / 内核 |
| --- | --- |
| `toa_centos6.5/` | CentOS 6.5（Linux 内核 2.6.x） |
| `toa_centos7/` | CentOS 7（Linux 内核 3.10.x） |
| `toa_common_kernel_3.0up/` | 通用版本（Linux 内核 3.0 及以上，Ubuntu 14/16、Suse 11/42 等） |
| `toa_linux-2.6.32-220.23.1.el6.x86_64.rs/` | 指定内核 `linux-2.6.32-220.23.1.el6.x86_64.rs` |
| `toa_freebsd13.2/` | FreeBSD 13.2 |

根据服务器系统版本选择最匹配的一套代码即可。

## 编译安装（Linux）

1. 进入对应版本目录，执行 `make`（要求已安装 gcc 与内核开发包）
2. 卸载旧版本模块（如有）：`rmmod toa`
3. 挂载编译好的模块：`insmod toa.ko`
4. 验证加载成功：`lsmod | grep toa`

### 缺少内核头文件

`make` 报错找不到 `/lib/modules/<内核版本>/build/` 时，说明缺少内核头文件，安装：

```shell
yum install kernel-devel
yum install kernel-headers
```

安装后 `/lib/modules/$(uname -r)/build/` 目录下应有正常内容。若该目录仍异常，说明扩展源码版本与运行内核不一致，此时需替换内核版本。

### 替换内核版本（可选）

替换内核存在风险，可能造成依赖底层的功能失效，替换后请充分测试。

```shell
# 安装与运行版本一致的内核四件套（安装时确认版本一致）
yum install kernel
yum install kernel-firmware
yum install kernel-devel
yum install kernel-headers

# 查询新内核的启动项名称
cat /boot/grub2/grub.cfg | grep menuentry

# 设置默认启动内核（示例）
grub2-set-default "CentOS Linux (3.10.0-862.11.6.el7.x86_64)"

# 重启生效
reboot

# 重启后确认当前内核
uname -r
```

确认内核切换成功后，回到 TOA 源码目录重新 `make` 即可。

## 开机自动加载（Linux）

make 成功后目录下会生成 `toa.ko`，先复制到内核模块目录：

```shell
cp toa.ko /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/
```

### CentOS

在 `/etc/sysconfig/modules/` 目录下创建脚本文件，用于重启时自动加载：

```shell
cd /etc/sysconfig/modules/
echo "insmod /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/toa.ko" > toa.modules
chmod 755 toa.modules
```

### Ubuntu 14

修改 `/etc/rc.local` 配置文件，在其中加入：

```shell
insmod /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/toa.ko
```

## FreeBSD 13.2

`toa_freebsd13.2/` 目录为 FreeBSD 13.2 移植版：通过 pfil(9) 入站钩子解析 SYN 中的 TOA option，替换 `tcp_usrreqs.pru_peeraddr` 使 `getpeername()` 返回真实地址，配置与统计通过 `sysctl net.inet.toa.*`。

```shell
# 构建需安装 /usr/src 源码树
cd toa_freebsd13.2
make

# 加载模块
kldload ./toa.ko

# 配置回源地址网段（不配置则对所有 SYN 生效）
sysctl net.inet.toa.scope="10.0.0.0/8"
```

详细说明（构建、配置、统计、行为边界）见 `toa_freebsd13.2/README.md`。

纯逻辑单元测试（TCP option 解析、scope 解析、哈希）可在任意带 C11 编译器的机器上运行，无需 FreeBSD：

```shell
make -C toa_freebsd13.2/tests test
```

## 其他

有任何建议请与我们留言。
