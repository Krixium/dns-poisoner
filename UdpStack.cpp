#include "UdpStack.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "checksum.h"

// The size of a UDP header
const unsigned short UdpStack::UDP_HDR_LEN = 8;

/*
 * UdpStack constructor. The UdpStack class is a class the wraps the IP/UDP network stack to make
 * crafting packets a simpler task.
 *
 * Params:
 *      const struct in_addr &saddr: The source address.
 *
 *      const struct in_addr &daddr: The destination address.
 *
 *      const short &sport: The source port.
 *
 *      const short &dport: The destination port.
 *
 *      const UCharVector: The UDP payload.
 */
UdpStack::UdpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const UCharVector &payload) {
    // fill the ip header
    this->ip.ihl = 5;
    this->ip.version = 4;
    this->ip.tos = 0;
    this->ip.id = (int)(244.0 * rand() / (RAND_MAX + 1.0));
    this->ip.frag_off = 0;
    this->ip.ttl = 64;
    this->ip.protocol = IPPROTO_UDP;
    this->ip.check = 0;
    this->ip.saddr = saddr.s_addr;
    this->ip.daddr = daddr.s_addr;
    this->ip.check = in_cksum((unsigned short *)&this->ip, this->ip.ihl * 4);

    // fill the udp header
    this->udp.source = htons(sport);
    this->udp.dest = htons(dport);
    this->udp.len = htons(UdpStack::UDP_HDR_LEN + payload.size());

    // calculate checksum
    this->calcChecksum();

    // fill the total length in ip header
    short totalLen = this->ip.ihl * 4 + UdpStack::UDP_HDR_LEN + payload.size();
    this->ip.tot_len = htons(totalLen);

    // copy the payload
    this->payload.resize(payload.size());
    for (int i = 0; i < payload.size(); i++) {
        this->payload.push_back(payload[i]);
    }
}

/*
 * Gets the raw bytes of the packet which will be ready to be sent on the network.
 *
 * Returns:
 *      The byte vector that reporesnents the packet.
 */
UCharVector UdpStack::getPacket() {
    const int ipLen = this->ip.ihl * 4;

    UCharVector packet;
    packet.resize(ntohs(this->ip.tot_len));

    memcpy(packet.data(), (char *)&this->ip, ipLen);
    memcpy(packet.data() + ipLen, (char *)&this->udp, UdpStack::UDP_HDR_LEN);
    memcpy(packet.data() + ipLen + UdpStack::UDP_HDR_LEN, (char *)this->payload.data(),
           this->payload.size());

    return packet;
}

/*
 * Calculates and fills the checksum in the UDP header.
 */
void UdpStack::calcChecksum() {
    struct UdpPseudoHeader pseudo_header;

    pseudo_header.srcAddr = this->ip.saddr;
    pseudo_header.dstAddr = this->ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udpLen = htons(this->udp.len);
    memcpy((char *)&pseudo_header.udp, (char *)&this->udp, ntohs(this->udp.len));

    this->udp.check = in_cksum((unsigned short *)&pseudo_header, sizeof(struct UdpPseudoHeader));
}
