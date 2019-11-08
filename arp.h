#ifndef ARP_H
#define ARP_H

#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

struct __attribute__((packed)) arp_header {
    unsigned short arp_hd;
    unsigned short arp_pr;
    unsigned char arp_hdl;
    unsigned char arp_prl;
    unsigned short arp_op;
    unsigned char arp_sha[6];
    unsigned char arp_spa[4];
    unsigned char arp_dha[6];
    unsigned char arp_dpa[4];
};

void forgeArp(const unsigned char *atkMac, const struct in_addr *srcIp, const unsigned char *dstMac,
              const struct in_addr *dstIp, struct arp_header *arpPkt);

#endif
