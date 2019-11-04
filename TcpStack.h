#ifndef TCP_STACK_H
#define TCP_STACK_H

#include <vector>

#include <linux/ip.h>
#include <linux/tcp.h>

using UCharVector = std::vector<unsigned char>;

struct TcpPseudoHeader {
    unsigned int srcAddr;
    unsigned int dstAddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcpLen;
    struct tcphdr tcp;
};

class TcpStack {
public:
    static const unsigned char FIN_FLAG;
    static const unsigned char SYN_FLAG;
    static const unsigned char RST_FLAG;
    static const unsigned char PSH_FLAG;
    static const unsigned char ACK_FLAG;
    static const unsigned char URG_FLAG;
    static const unsigned char ECE_FLAG;
    static const unsigned char CWR_FLAG;

    struct iphdr ip;
    struct tcphdr tcp;
    UCharVector payload;

public:
    TcpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
             const short &dport, const unsigned int &seqNum, const unsigned int &ackNum,
             const unsigned char &tcpFlags, const UCharVector &payload);

    UCharVector getPacket();

private:
    void calcChecksum();
};

#endif
