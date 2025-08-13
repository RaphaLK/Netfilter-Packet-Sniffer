# Netfilter Packet Sniffer
## Kernel Module for a TCP/UDP Packet Sniffer using the Netfilter Framework
### TO RUN:
1. make
2. insmod sniffer.ko
3. ping any host/just let run
4. sudo dmesg
5. You can observe statistics by running cat /proc/sniffer_stats
6. rmmod sniffer
