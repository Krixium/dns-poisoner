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

#include <endian.h>
#include <stdint.h>

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

int forgeDns(const dnshdr *dnsHeader, const struct in_addr *fakeAddr, unsigned char *output);
