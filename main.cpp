#include <iostream>

#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#include "NetworkEngine.h"
#include "UdpStack.h"

#include "arp.h"
#include "dns.h"

void arpCallback(const struct pcap_pkthdr *header, const unsigned char *packet);
void dnsCallback(const struct pcap_pkthdr *header, const unsigned char *packet);

int main(int argc, const char *argv[]) {
    NetworkEngine ipEngine;
    NetworkEngine arpEngine;

    ipEngine.LoopCallbacks.push_back(dnsCallback);
    arpEngine.LoopCallbacks.push_back(arpCallback);
    arpEngine.startSniff(NetworkEngine::ARP_FILTER);
    ipEngine.startSniff(NetworkEngine::IP_FILTER);

    sleep(5);

    ipEngine.stopSniff();
    arpEngine.stopSniff();

    return 0;
}

/*
 * Simple callback that just displays some basic arp fields as a proof-of-concept
 */
void arpCallback(const struct pcap_pkthdr *header, const unsigned char *packet) {
    int i;
    arphdr_t *arpheader = NULL;
    arpheader = (struct arphdr *)(packet + 14);

    printf("\n\nReceived Packet Size: %d bytes\n", header->len);
    printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
    printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
    printf("Operation: %s\n",
           (ntohs(arpheader->oper) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

    /* If is Ethernet and IPv4, print packet contents */
    if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
        printf("Sender MAC: ");

        for (i = 0; i < 6; i++)
            printf("%02X:", arpheader->sha[i]);

        printf("\nSender IP: ");

        for (i = 0; i < 4; i++)
            printf("%d.", arpheader->spa[i]);

        printf("\nTarget MAC: ");

        for (i = 0; i < 6; i++)
            printf("%02X:", arpheader->tha[i]);

        printf("\nTarget IP: ");

        for (i = 0; i < 4; i++)
            printf("%d.", arpheader->tpa[i]);

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
