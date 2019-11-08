#include "NetworkEngine.h"

#include <cstring>
#include <iostream>

#include <sys/ioctl.h>
#include <unistd.h>

#include "TcpStack.h"
#include "UdpStack.h"

// sendto flags
const int NetworkEngine::SEND_FLAGS = 0;
// maximum network transmission size
const int NetworkEngine::MTU = 1500;

// pcap filter for IP frames
const char *NetworkEngine::IP_FILTER = "ip";
// pcap filter for ARP frames
const char *NetworkEngine::ARP_FILTER = "arp";

/*
 * Constructor for NetworkEngine. The network engine is a class that handles pcap packet sniffing as
 * well as sending crafted TCP and UDP packets using raw sockets.
 */
NetworkEngine::NetworkEngine(const char *interfaceName)
    : pcapPromiscuousMode(0), pcapLoopDelay(1), session(nullptr), sniffThread(nullptr) {
    this->getInterfaceInfo(interfaceName);
    this->openRawSocket();
    this->openArpSocket();
}

/*
 * Deconstructor for NetworkEngine.
 */
NetworkEngine::~NetworkEngine() {
    if (this->rawSocket != -1) {
        close(this->rawSocket);
    }

    if (this->arpSocket != -1) {
        close(this->arpSocket);
    }

    this->stopSniff();
}

/*
 * Sends a TCP packet with the given parameters.
 *
 * Params:
 *      const std::string &saddr: The dotted decimal string of the source address.
 *
 *      const std::string &daddr: The dotted decimal string of the destination address.
 *
 *      const short &sport: The source port.
 *
 *      const short &dport: The destination port.
 *
 *      const unsigned char &tcpFlags: The TCP flags to use.
 *
 *      const UCharVector &payload: The TCP payload.
 *
 * Returns:
 *      The number of bytes sent.
 */
int NetworkEngine::sendTcp(const std::string &saddr, const std::string &daddr, const short &sport,
                           const short &dport, const unsigned char &tcpFlags,
                           const UCharVector &payload) {
    if (this->rawSocket == -1) {
        return 0;
    }

    struct sockaddr_in sin;
    struct sockaddr_in sinSrc;
    struct sockaddr_in sinDst;

    if (inet_pton(AF_INET, saddr.c_str(), &sinSrc.sin_addr) != 1) {
        return 0;
    }

    if (inet_pton(AF_INET, daddr.c_str(), &sinDst.sin_addr) != 1) {
        return 0;
    }

    srand(time(NULL));
    unsigned int seq_num = rand() % 0xFFFFFFFF;
    unsigned int ack_num = rand() % 0xFFFFFFFF;

    TcpStack tcpStack(sinSrc.sin_addr, sinDst.sin_addr, sport, dport, seq_num, ack_num, tcpFlags,
                      payload);
    UCharVector packet = tcpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU) {
        return 0;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = tcpStack.tcp.source;
    sin.sin_addr.s_addr = tcpStack.ip.daddr;

    return sendto(this->rawSocket, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

/*
 * Sends a UDP packet with the given parameters.
 *
 * Params:
 *      const std::string &saddr: The dotted decimal string of the source address.
 *
 *      const std::string &daddr: The dotted decimal string of the destination address.
 *
 *      const short &sport: The source port.
 *
 *      const short &dport: The destination port.
 *
 *      const UCharVector &payload: The UDP payload.
 *
 * Returns:
 *      The number of bytes sent.
 */
int NetworkEngine::sendUdp(const std::string &saddr, const std::string &daddr, const short &sport,
                           const short &dport, const UCharVector &payload) {
    if (this->rawSocket == -1) {
        return 0;
    }

    struct sockaddr_in sin;
    struct sockaddr_in sinSrc;
    struct sockaddr_in sinDst;

    if (inet_pton(AF_INET, saddr.c_str(), &sinSrc.sin_addr) != 1) {
        return 0;
    }

    if (inet_pton(AF_INET, daddr.c_str(), &sinDst.sin_addr) != 1) {
        return 0;
    }

    UdpStack udpStack(sinSrc.sin_addr, sinDst.sin_addr, sport, dport, payload);
    UCharVector packet = udpStack.getPacket();

    if (packet.size() > NetworkEngine::MTU) {
        return 0;
    }

    sin.sin_family = AF_INET;
    sin.sin_port = udpStack.udp.source;
    sin.sin_addr.s_addr = udpStack.ip.daddr;

    return sendto(this->rawSocket, packet.data(), packet.size(), NetworkEngine::SEND_FLAGS,
                  (struct sockaddr *)&sin, sizeof(sin));
}

int NetworkEngine::sendArp(const struct arp_header &arpPkt) {
    char buffer[42];
    struct ethhdr *eth = (struct ethhdr *)buffer;

    // fill sock addr
    struct sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;           // this is always AF_PACKET
    sockAddr.sll_protocol = htons(ETH_P_ARP);  // ethernet
    sockAddr.sll_ifindex = this->ifindex;      // interface index
    sockAddr.sll_hatype = htons(ARPHRD_ETHER); // hardware address type
    sockAddr.sll_pkttype = PACKET_HOST;        // packet type(host, broadcast, multicast)
    sockAddr.sll_halen = ETH_ALEN;             // ethernet address length
    sockAddr.sll_addr[6] = 0x00;               // always 0
    sockAddr.sll_addr[7] = 0x00;               // always 0

    // copy arp header into buffer
    memcpy(buffer + sizeof(struct ethhdr), &arpPkt, sizeof(struct arp_header));

    // set the ethernet header
    memcpy(&eth->h_dest, arpPkt.arp_dha, ETH_ALEN);
    memcpy(&eth->h_source, arpPkt.arp_sha, ETH_ALEN);
    eth->h_proto = htons(ETH_P_ARP);

    // send
    return sendto(this->arpSocket, buffer, 42, 0, (struct sockaddr *)&sockAddr,
                  sizeof(struct sockaddr_ll));
}

/*
 * Starts the PCAP sniffing thread.
 *
 * Params:
 *      const char *filter: The filter string.
 *
 */
void NetworkEngine::startSniff(const char *filter) {
    this->sniffThread = new std::thread(&NetworkEngine::runSniff, this, filter);
}

/*
 * Stops the PCAP sniff loop.
 */
void NetworkEngine::stopSniff() {
    if (this->sniffThread != nullptr) {
        pcap_breakloop(this->session);
        if (this->sniffThread->joinable()) {
            this->sniffThread->join();
        }
        delete this->sniffThread;
        this->sniffThread = nullptr;
    }
}

void NetworkEngine::getInterfaceInfo(const char *interfaceName) {
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    if (sd <= 0) {
        close(sd);
    }

    if (strlen(interfaceName) > (IFNAMSIZ - 1)) {
        close(sd);
    }

    strcpy(ifr.ifr_name, interfaceName);

    // get interface index using name
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        close(sd);
    }

    this->ifindex = ifr.ifr_ifindex;

    // get MAC address of the interface
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        close(sd);
    }

    // copy mac address to output
    memcpy(this->mac, ifr.ifr_hwaddr.sa_data, 6);

    if (sd > 0) {
        close(sd);
    }
}

void NetworkEngine::openArpSocket() {
    struct sockaddr_ll sll;

    this->arpSocket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = this->ifindex;

    bind(this->arpSocket, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll));
}

void NetworkEngine::openRawSocket() { this->rawSocket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW); }

/*
 * The main entry point of the sniffing thread. Handles initialization of the pcap_loop.
 *
 * Params:
 *      const char *filter: The filter to use for the pcap_loop.
 */
void NetworkEngine::runSniff(const char *filter) {
    int i;

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
            for (pcap_addr_t *addr = temp->addresses; addr; addr = addr->next) {
                if (addr->addr->sa_family == AF_INET) {
                    memcpy(&this->localAddrss, (char *)addr->addr, sizeof(struct sockaddr_in));
                }
            }
            break;
        }
    }

    this->session =
        pcap_open_live(temp->name, BUFSIZ, this->pcapPromiscuousMode, this->pcapLoopDelay, errBuff);
    if (!this->session) {
        std::cerr << "Could not open device: " << errBuff << std::endl;
        return;
    }

    if (pcap_compile(this->session, &filterProgram, filter, 0, netAddr)) {
        std::cerr << "Error calling pcap_compile" << std::endl;
        return;
    }

    if (pcap_setfilter(this->session, &filterProgram) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return;
    }

    pcap_loop(this->session, 0, &gotPacket, (unsigned char *)this);

    pcap_freealldevs(allDevs);
}

/*
 * The main pcap_loop callback function. Executes all callback functions stored in the network
 * engine given.
 *
 * Params:
 *      unsigned char *args: The user supplied arguments.
 *
 *      const struct pcap_pkthdr *header: The pcap packet header passed by the pcap_loop.
 *
 *      const unsigned char *packet: The network packet sniffed by pcap_loop.
 */
void gotPacket(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    NetworkEngine *netEngine = (NetworkEngine *)args;
    for (int i = 0; i < netEngine->LoopCallbacks.size(); i++) {
        (netEngine->LoopCallbacks[i])(header, packet);
    }
}
