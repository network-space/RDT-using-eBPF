//kernel.header
//Have to change this file and recompile eBPF programs RK and SKI for trying exoerşnebt parameters
#define fs 4      //file size
#define pds 2     //packet data size
#define pcif (fs/pds)   //packet count in files
#define re 1      //repetption of experiment
#define acc 2     //ack cumulativity      (max. number of acks inside a ack packet)