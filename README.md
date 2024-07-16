# RDT using eBPF
**reliable data transfer using extended Berkeley Packet Filter**

Hereby we propose a system for RDT using eBPF. We suggest that this approach not only enables faster reliable transfers, but also supports a paradigm we name as "dynamic kernel-level systems design". We foresee that this paradigm enables the opportunity for light-speed development and deployment of core functionalities which had been hidden under the burden of designing modules into operating system kernels where endless dependencies and recompilation processes slows down the development and lifts the threshold of ability to contribute.

## Branches

### main
TODO: Will be for the generic use of the system.

### ven (virtual ethernet)
A version of the system for experimenting on virtual ethernet pairs.

### en-en (ethernet-ethernet)
A version of the system for ethernet-ethernet connection between 2 PCs.

## The Reliable Communication System
First of all, please note that this system is not stabilized yet. But here is the current description of how the system works:

- The proposed system has 4 components and 2 headers. For comparison, 2 additional components in userspace exist.

### Proposed System

#### most important Meta-Parameters
- **pts**: how many bytes of file is embedded inside a packet
- **acc**: ack cumulativity (how many packet's acks are sent altogether at max.)
- ring buffer size (to be explained later)
- asynchronousity

#### additional Parameters for Experiment (or additional Experiment Axises)
- file size
- communication level
  - Embedding Inside Raw Ethernet Packets: The minimal ethernet packet is 14 bytes. This version just obeys this rule of ethernet packets and assumes there is only one sender and receiver. So the packet does not start with sender and receiver MAC addresses, rather, it starts with the raw communication data.
  - Only Ethernet Destination: Assuming multiple destionations can exist. The first 6 bytes are for the destionation MAC, rest is data.
  - Ethernet Destination and Source: The transition follows. First 12 bytes are reserved for source and destination, but the rest is data.
  - Ethernet Packet: The 2 remaining minimal ethernet bytes are used for specifying ethertype. The remaining is data. This type of communication is enough for a -closed- network of devices (whose MAC addresses are not clashing) to be able to use our proposed solution for internal reliable communications and still be able to communicate in other ways. Our ethertype is 1501. So any packet whose ethertype is 1501 is assumed as a reliable-eBPF communication.
  - IPv6 Packet: The packet has a minimal IPv6 header with communication protocol number 146. The rest is data. Thus, in theory, this packet can be used in communication over internet. However, in practise, some routers will silently drop such packets. This is called ossification in data communications over internet. The security measures made some portions of packets redundant: Basically we are now limited to use specific protocols, otherwise our packet is dropped.
  - UDP over IPv6: The packet is a UDP packet sent over IPv6. This is what Google's QUIC uses to overcome ossification. So basically our packet will be a UDP packet over IPv6, practically enabling reliable communication between supporting devices. This version is the version we will test over real internet.
- checksum calculation on/off
- repetition
- optimization flags for each program of the proposed system and the testing system
- the real or simulated **environmental condition parameters** such as packet delay, loss, corruption, duplication,..
- varying testing environments such as virtual ethernet pairs, cable connection of 2 computers, 2 virtual machines, wireless local communication, IP communication of 2 remote computers

#### Components
The components are explained in steps 1,2,3,4... Follow them for easier understanding of each path. 
##### Sender
###### Userspace Program
##### 1
Creates a array in memory each byte of whom is a random 8bit value. Then creates a packet buffer and fills it with data that will not change over packets. Sends the file in packets defined as:
< frame | packet indice | data >
The sizes vary according to parameters of the experiment -and the program. (goto **2**) Then enters a loop iterations of whose are as follows:
1. Check if any Ack or Nack packet has come.
##### 5
2. If a Ack packet has come; set the packet indice as acknowledged.
##### 6
3. If a NACK packet has come; unset the packet indice if it has been set as acknowledged.
3. Then traverse the packets to see if any non-acknowledged packet remains, if so, goto 1. Else, the transfer has been finished.

###### eBPF.XDP Program
##### 4
Receives a cumulative Ack packet or a NACK packet.
- Cumulative ack packets are sent as individual ack packets to the userspace program thru a eBPF ring buffer. (goto **5**)
- NACK packets are sent as-is to the userspace thru the same eBPF ring buffer. (goto **6**)

##### Receiver
###### eBPF.XDP Program
##### 2
If the packet is interested, first delivers the packet to the userspace using eBPF ring buffers. (goto **3**) Then if cumulative Ack count is reached, manipulates the packet so that the packet becomes a cumulative Ack packet. Using XDP_TX, sends the ack packet to the sender. (goto **4**)
###### Userspace Program
##### 3
Receives packets from ring buffer. Sometimes the ring buffer sends partial information of a packet. So the size of the ring buffer is not enough. If it detects this, sends a NACK message to the sender for the specific packet. (goto **4**) Else, stores the packet.


