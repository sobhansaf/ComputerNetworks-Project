# ComputerNetworks-Project
a simple sniffer and a port analyzer

In order to run network sniffer, run the following commands:
```
sudo ifconfig <interface> promisc
sudo python3 main.py
```

This network sniffer does not support all of the protocols. Some of the protocols supported are HTTP, ICMP, DNS and ARP.

In order to run port analyzer, `netifaces` module should be installed. To run the port analyzer, run:
```
python3 main.py dst=<destination> delay=<time to wait for response> mode=<mode> iface=<network interface> ports=<range of ports>
```

Availabe modes are:
- s: SYN scan
- c: Connect scan
- f: Fin scan
- W: Window scan
- a: ACK scan

For example you can run the following command to scan all open ports in range 70-90 from example.com:
```
python3 main2.py dst=example.com mode=s ports=70-90 iface=wlp2s0 delay=1
```
which outputs:
```
---Target: example.com---
---SYN scan---
---Range of ports: (70, 90) ---
---interface set to wlp2s0---
---Delay: 1.0---
******************************
      Starting SYN scan       
....................


Port numbers { 80 } sent back SYN/ACK tcp packets!


******************************
```
