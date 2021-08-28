## NetFlow Based System For Detecting DoS and DDoS Attacks

### Requirements

 * [Python 2.5 or higher](http://www.python.org/download/)
 * [Scapy tool v2.x](http://www.secdev.org/projects/scapy/doc/installation.html)

### Installation

It is needed to copy the ***"netflowV9.py"*** file into ***"/usr/local/lib/python2.x/site-packages/scapy/layers/"*** for adding the Cisco NetFlow protocol to Scapy tools.

```shell
~$ cp netflowV9.py /usr/local/lib/python2.x/site-packages/scapy/layers/netflowV9.py
```
```shell
~$ cp dosflowsys.py .
```

```shell
~$ mkdir servers # to create the "servers" that contains configuration files for each server to be probed
```

It is needed to define a configuration file for each server into "servers" directory

***An example is given below:***

```PORT_DST = 53, 80, 22 # listening and open port numbers
MAX_TCP_CLIENTS = 4000 # maximum number of TCP clients supported by the server
MAX_LATENCY = 100 # maximum acceptable latency
MAX_SYN_BACKLOG = 2048 # backlog queue size
```

### Usage

```shell
~$ python2.x dosflowsys.py
```
