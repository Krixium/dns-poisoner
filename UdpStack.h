#ifndef UDP_STACK_H
#define UDP_STACK_H

#include <vector>

#include <linux/ip.h>
#include <linux/udp.h>

using UCharVector = std::vector<unsigned char>;

struct UdpPseudoHeader {
    unsigned int srcAddr;
    unsigned int dstAddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udpLen;
    struct udphdr udp;
};

class UdpStack {
public:
    static const unsigned short UDP_HDR_LEN;

    struct iphdr ip;
    struct udphdr udp;
    UCharVector payload;

public:
    UdpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
             const short &dport, const UCharVector &payload);

    UCharVector getPacket();

private:
    void calcChecksum();
};


#endif
