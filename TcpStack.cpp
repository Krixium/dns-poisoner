#include "TcpStack.h"

#include <cstring>

#include <arpa/inet.h>
#include <stdlib.h>

#include "checksum.h"

// TCP flags
const unsigned char TcpStack::FIN_FLAG = 0x01;
const unsigned char TcpStack::SYN_FLAG = 0x02;
const unsigned char TcpStack::RST_FLAG = 0x04;
const unsigned char TcpStack::PSH_FLAG = 0x08;
const unsigned char TcpStack::ACK_FLAG = 0x10;
const unsigned char TcpStack::URG_FLAG = 0x20;
const unsigned char TcpStack::ECE_FLAG = 0x40;
const unsigned char TcpStack::CWR_FLAG = 0x80;

/*
 * TcpStack constructor. The TcpStack class is a class the wraps the IP/TCP network stack to make
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
 *      const unsigned int &seqNum: The TCP sequence number.
 *
 *      const unsigned int &ackNum: The TCP ack sequence number.
 *
 *      const unsgined char &tcpFlags: The TCP flag bit pattern.
 *
 *      const UCharVector: The TCP payload.
 */
TcpStack::TcpStack(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                   const short &dport, const unsigned int &seqNum, const unsigned int &ackNum,
                   const unsigned char &tcpFlags, const UCharVector &payload) {
    // fill ip header
    this->ip.ihl = 5;
    this->ip.version = 4;
    this->ip.tos = 0;
    this->ip.id = (int)(244.0 * rand() / (RAND_MAX + 1.0));
    this->ip.frag_off = 0;
    this->ip.ttl = 64;
    this->ip.protocol = IPPROTO_TCP;
    this->ip.check = 0;
    this->ip.saddr = saddr.s_addr;
    this->ip.daddr = daddr.s_addr;
    this->ip.check = in_cksum((unsigned short *)&this->ip, this->ip.ihl * 4);

    // fill tcp header
    this->tcp.source = htons(sport);
    this->tcp.dest = htons(dport);
    this->tcp.seq = htonl(seqNum);
    this->tcp.ack_seq = htonl(ackNum);
    this->tcp.doff = 5;
    this->tcp.fin = tcpFlags & TcpStack::FIN_FLAG ? 1 : 0;
    this->tcp.syn = tcpFlags & TcpStack::SYN_FLAG ? 1 : 0;
    this->tcp.rst = tcpFlags & TcpStack::RST_FLAG ? 1 : 0;
    this->tcp.psh = tcpFlags & TcpStack::PSH_FLAG ? 1 : 0;
    this->tcp.ack = tcpFlags & TcpStack::ACK_FLAG ? 1 : 0;
    this->tcp.urg = tcpFlags & TcpStack::URG_FLAG ? 1 : 0;
    this->tcp.ece = tcpFlags & TcpStack::ECE_FLAG ? 1 : 0;
    this->tcp.cwr = tcpFlags & TcpStack::CWR_FLAG ? 1 : 0;
    this->tcp.res1 = 0;
    this->tcp.window = htons(512);
    this->tcp.check = 0;
    this->tcp.urg_ptr = 0;

    // calculate checksum
    this->calcChecksum();

    // fill total length in ip header
    this->ip.tot_len = htons(this->ip.ihl * 4 + this->tcp.doff * 4 + payload.size());

    // copy the payload
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

UCharVector TcpStack::getPacket() {
    const int ipLen = this->ip.ihl * 4;
    const int tcpLen = this->tcp.doff * 4;

    UCharVector packet;
    packet.resize(ntohs(this->ip.tot_len));

    memcpy(packet.data(), (char *)&this->ip, ipLen);
    memcpy(packet.data() + ipLen, (char *)&this->tcp, tcpLen);
    memcpy(packet.data() + ipLen + tcpLen, this->payload.data(), this->payload.size());

    return packet;
}

/*
 * Calculates and fills the checksum in the TCP header.
 */
void TcpStack::calcChecksum() {
    struct TcpPseudoHeader pseudoHeader;

    pseudoHeader.srcAddr = this->ip.saddr;
    pseudoHeader.dstAddr = this->ip.daddr;
    pseudoHeader.placeholder = 0;
    pseudoHeader.protocol = IPPROTO_TCP;
    pseudoHeader.tcpLen = htons(this->tcp.doff * 4);
    memcpy((char *)&pseudoHeader.tcp, (char *)&this->tcp, this->tcp.doff * 4);

    this->tcp.check = in_cksum((unsigned short *)&pseudoHeader, sizeof(struct TcpPseudoHeader));
}
