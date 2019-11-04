#ifndef NETWORK_ENGINE_H
#define NETWORK_ENGINE_H

#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <pcap/pcap.h>

using UCharVector = std::vector<unsigned char>;

class NetworkEngine {
private:
    static const int SEND_FLAGS;
    static const int MTU;

    struct sockaddr_in localAddrss;

    int pcapPromiscuousMode;
    int pcapLoopDelay;
    int sd;

    pcap_t *session;

    std::thread *sniffThread;

public:

    static const char *IP_FILTER;
    static const char *ARP_FILTER;

    std::vector<std::function<void(const struct pcap_pkthdr *, const unsigned char *)>> LoopCallbacks;

public:
    NetworkEngine();
    ~NetworkEngine();

    int sendTcp(const std::string &saddr, const std::string &daddr, const short &sport,
                const short &dport, const unsigned char &tcpFlags, const UCharVector &payload);

    int sendUdp(const std::string &saddr, const std::string &daddr, const short &sport,
                const short &dport, const UCharVector &payload);

    void startSniff(const char *filter);

    void stopSniff();

private:
    void runSniff(const char *filter);
};

void gotPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
