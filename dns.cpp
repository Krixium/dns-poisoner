#include "dns.h"

#include <arpa/inet.h>
#include <string.h>

int forgeDns(const dnshdr *dnsHeader, const struct in_addr *fakeAddr, unsigned char *output) {
    int size;
    dnsquery *query = (dnsquery *)((unsigned char *)dnsHeader + sizeof(dnshdr));

    ((dnshdr *)output)->id = dnsHeader->id;
    ((dnshdr *)output)->qcount = htons(1);
    ((dnshdr *)output)->ancount = htons(1);
    ((dnshdr *)output)->nscount = htons(0);
    ((dnshdr *)output)->adcount = htons(0);
    // flags
    output[2] = 0x81;
    output[3] = 0x80;

    // get the total size of the query
    for (size = 2 + 2 + 2; query->qname[size]; size++);

    // copy the query to the output
    memcpy(output + 12, query, size);
    size += 12;

    // create the dns answer
    memcpy(output + size, "\xc0\x0c", 2); // pointer to q name
    size += 2;
    memcpy(output + size, "\x00\x01", 2); // type
    size += 2;
    memcpy(output + size, "\x00\x01", 2); // class
    size += 2;
    memcpy(output + size, "\x00\x00\x00\x22", 4); // ttl
    size += 2;
    memcpy(output + size, "\x00\x04", 4); // rdata len
    size += 2;
    memcpy(output + size, &fakeAddr, 4); // rdata
    size += 2;

    return size;
}
