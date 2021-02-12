This utility mirrors traffic from tun interface to eth. Due to tun interface has no ethernet headers we need to add such info. To implement this feature it uses just zeros as dst and src mac addresses.  
If source interface has ethernet headers it sends packets as is without any modifications.  
## Important:
This uses libpcap to capture packets and send them to ethernet interface. If you need high performance you should use different solution, for example, dpdk or netmap.

## To build:
```
$ cmake CMakeLists.txt
$ make
```
## To use:
```
# ip2eth -i <from_device> -o <to_device>  
```
It works in background. To stop program just send kill signal.
