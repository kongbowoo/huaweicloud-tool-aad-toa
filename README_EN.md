# huaweicloud-tool-aad-toa

简体中文 | [English](README_EN.md)

Dedicated TOA (TCP Option Address) kernel module for Huawei Cloud Advanced Anti-DDoS ([AAD](https://www.huaweicloud.com/product/aad.html)), optimized on top of the open-source TOA module originally developed by Taobao. It resolves the real client source IP on the server side and can be built and installed directly on Linux / FreeBSD servers.

## How It Works

With AAD (LVS FULLNAT) proxying, the server sees the proxy address as the TCP peer. The proxy carries the real client `{IP, Port}` in a TCP option (opcode 254) on the SYN packet it sends to the origin server. With this module loaded, the server:

1. Intercepts the SYN packet and parses the real address from option 254
2. Returns the real client `{IP, Port}` when the application calls `getpeername()`

## Version Selection

| Directory | Target System / Kernel |
| --- | --- |
| `toa_centos6.5/` | CentOS 6.5 (Linux kernel 2.6.x) |
| `toa_centos7/` | CentOS 7 (Linux kernel 3.10.x) |
| `toa_common_kernel_3.0up/` | Generic (Linux kernel 3.0 and above, e.g. Ubuntu 14/16, Suse 11/42) |
| `toa_linux-2.6.32-220.23.1.el6.x86_64.rs/` | Specific kernel `linux-2.6.32-220.23.1.el6.x86_64.rs` |
| `toa_freebsd13.2/` | FreeBSD 13.2 |

Pick the code base that best matches your server.

## Build and Install (Linux)

1. Enter the matching directory and run `make` (requires gcc and kernel development packages)
2. Remove a previously loaded module if any: `rmmod toa`
3. Load the freshly built module: `insmod toa.ko`
4. Verify: `lsmod | grep toa`

### Missing Kernel Headers

If `make` fails with a missing `/lib/modules/<kernel-version>/build/` directory, install the kernel development packages:

```shell
yum install kernel-devel
yum install kernel-headers
```

Afterwards `/lib/modules/$(uname -r)/build/` should contain a valid source tree. If it is still broken, the installed kernel headers do not match the running kernel; switch to a matching kernel version as described below.

### Switching Kernel Versions (Optional)

Replacing the kernel carries risk: features that depend on the old kernel may stop working. Test thoroughly after switching.

```shell
# Install the kernel set matching the running version (verify versions match during install)
yum install kernel
yum install kernel-firmware
yum install kernel-devel
yum install kernel-headers

# Find the boot entry name of the new kernel
cat /boot/grub2/grub.cfg | grep menuentry

# Set the default boot kernel (example)
grub2-set-default "CentOS Linux (3.10.0-862.11.6.el7.x86_64)"

# Reboot to take effect
reboot

# Confirm the running kernel after reboot
uname -r
```

Once the kernel is switched, go back to the TOA source directory and run `make` again.

## Loading at Boot (Linux)

After a successful `make`, copy `toa.ko` into the kernel module directory:

```shell
cp toa.ko /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/
```

### CentOS

Create a script file under `/etc/sysconfig/modules/` so the module is loaded at boot:

```shell
cd /etc/sysconfig/modules/
echo "insmod /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/toa.ko" > toa.modules
chmod 755 toa.modules
```

### Ubuntu 14

Edit `/etc/rc.local` and add the following line:

```shell
insmod /lib/modules/$(uname -r)/kernel/net/netfilter/ipvs/toa.ko
```

## FreeBSD 13.2

The `toa_freebsd13.2/` directory is the FreeBSD 13.2 port: a pfil(9) inbound hook parses the TOA option from SYN packets, and `tcp_usrreqs.pru_peeraddr` is replaced so `getpeername()` returns the real address. Configuration and statistics are exposed via `sysctl net.inet.toa.*`.

```shell
# Building requires the /usr/src tree
cd toa_freebsd13.2
make

# Load the module
kldload ./toa.ko

# Configure proxy source scopes (empty means all SYN packets)
sysctl net.inet.toa.scope="10.0.0.0/8"
```

See `toa_freebsd13.2/README.md` for details (build, configuration, statistics, behavioral notes).

Unit tests for the pure logic layer (TCP option parsing, scope parsing, hashing) run on any machine with a C11 compiler, no FreeBSD required:

```shell
make -C toa_freebsd13.2/tests test
```

## Feedback

Feel free to leave comments or suggestions.
