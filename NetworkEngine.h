#ifndef NETWORK_ENGINE_H
#define NETWORK_ENGINE_H

#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <pcap/pcap.h>

#include "arp.h"

using UCharVector = std::vector<unsigned char>;

class NetworkEngine {
private:
    static const int SEND_FLAGS;
    static const int MTU;

    struct sockaddr_in localAddrss;

    int pcapPromiscuousMode;
    int pcapLoopDelay;

    int rawSocket;
    int arpSocket;

    int ifindex;
    unsigned char mac[ETH_ALEN];
    struct in_addr ip;

    pcap_t *session;

    std::thread *sniffThread;

public:
    static const char *IP_FILTER;
    static const char *ARP_FILTER;

    std::vector<std::function<void(const struct pcap_pkthdr *, const unsigned char *)>>
        LoopCallbacks;

public:
    NetworkEngine(const char *interfaceName);
    ~NetworkEngine();

    int sendTcp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                const short &dport, const unsigned char &tcpFlags, const UCharVector &payload);

    int sendUdp(const struct in_addr &saddr, const struct in_addr &daddr, const short &sport,
                const short &dport, const UCharVector &payload);

    int sendArp(const struct arp_header &arpPkt);

    void startSniff(const char *filter);

    void stopSniff();

    const unsigned char *getMac();
    const struct in_addr *getIp();

private:
    void getInterfaceInfo(const char *interfaceName);

    void openRawSocket();

    void openArpSocket();

    void runSniff(const char *filter);
};

void gotPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
