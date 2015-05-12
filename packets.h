/*
 * Pedro Larbig, Alexander Oberle
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 3 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include <inttypes.h>

typedef unsigned char u_char;

#define BROADCAST "\xFF\xFF\xFF\xFF\xFF\xFF"
#define BATMAN_VERSION 0x0c
#define BATMAN_LEN 24

struct batman_packet {
        uint8_t  packet_type;
        uint8_t  version;  /* batman version field */
        uint8_t  flags;    /* 0x40: DIRECTLINK flag, 0x20 VIS_SERVER flag... */
        uint8_t  tq;
        uint32_t seqno;
        uint8_t  orig[6];
        uint8_t  prev_sender[6];
        uint8_t  ttl;
        uint8_t  num_hna;
        uint8_t  gw_flags;  /* flags related to gateway class */
        uint8_t  align;
} __attribute__((packed));

u_char *create_firsthop_packet(int *len, u_char *src, int seqnr, int hna_count, u_char *hnas);
u_char *create_packet(int *len, const u_char *ethsrc, int first_hop, int direct_link, u_char quality, int seqnr, const u_char *origin, const u_char *from, u_char ttl, u_char hna_count, const u_char *hnas_catted);
u_char *packet_append(u_char *pkt, int *len, int first_hop, int direct_link, u_char quality, int seqnr, u_char *origin, u_char *from, u_char ttl, u_char hna_count, u_char *hnas_catted);
void print_packetinfo(const u_char *packet, int len);
void print_mac(const u_char *mac);
