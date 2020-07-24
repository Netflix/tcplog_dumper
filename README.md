# tcplog_dumper

Gather the data from the [FreeBSD's tcp_log device](https://reviews.freebsd.org/rS331347).

## Usage example

Using a FreeBSD -head (r363032 minimum, to have the extra TCP stack headers installed),
compile a new kernel with BBR and extra TCP stack enabled:
```
# cat /usr/src/sys/amd64/conf/BBR
include GENERIC-NODEBUG

ident           BBR
options         TCPHPTS
options         RATELIMIT
makeoptions     WITH_EXTRA_TCP_STACKS=1

# cat /etc/src.conf
KERNCONF=BBR
MALLOC_PRODUCTION=yes
```

Build and install this customized kernel.
Checking for those files
* /boot/kernel/tcp_bbr.ko
* /boot/kernel/tcp_rack.ko

Load thoses modules during startup (sooner on /boot/loader.conf or later on /etc/rc.conf).
Example with the rc.conf:
```sysrc kld_list+="tcp_rack tcp_bbr"```

Configure the system to use BBR TCP stack by default:
```
echo 'net.inet.tcp.functions_default=bbr' >> /etc/sysctl.conf
```

Reboot and check if the system is using the BBR TCP stack:
```
# sysctl net.inet.tcp.functions_default
net.inet.tcp.functions_default: bbr
```

Enable BBR logging for all TCP sessions:

```
# sysctl net.inet.tcp.bb.log_auto_mode=4
# sysctl net.inet.tcp.bb.log_auto_all=1
# sysctl net.inet.tcp.bb.log_auto_ratio=1
```

Start tcplog_dumper:

```
# mkdir /var/log/tcplog_dumps
# chown nobody /var/log/tcplog_dumps
# tcplog_dumper
```

For each new TCP sessions, there will be multiples .pcapng files in the log directory:
You can use [read_bbrlog](https://github.com/Netflix/read_bbrlog) to interpret those files.
