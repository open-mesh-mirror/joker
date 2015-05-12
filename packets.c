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
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

#include "packets.h"

void print_mac(const u_char *mac) {
  printf("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_packetinfo(const u_char *packet, int len) {
  struct batman_packet *bp;
  uint8_t i;
  const u_char *cpos;
  
  printf("Packet from "); print_mac(packet + 6); printf("\n");
  printf("Packet to "); print_mac(packet); printf("\n");

  if ((packet[12] == 0x43) && (packet[13] == 0x05)) {
    cpos = packet + 14;  //Skip ethernet header
    while(cpos < (packet + len)) {
      bp = (struct batman_packet *) cpos;

      switch (bp->packet_type) {

      case 0x01:
        printf(" OGM Orig: "); print_mac(bp->orig);
        printf(" Direct: %d", (bp->flags & 0x40) >> 6);
        printf(" Firsthop: %d", (bp->flags & 0x10) >> 4);
        printf(" Quality: %3d", bp->tq);
        printf(" Over: "); print_mac(bp->prev_sender);
        printf(" TTL: %d", bp->ttl);
        printf(" HNAcount: %d", bp->num_hna);
        printf(" HNAs: ");
        for (i=0; i<bp->num_hna; i++) {
          print_mac(cpos + BATMAN_LEN + (6 * i));
          printf(" ");
        }
        printf(" SeqNr: %d\n", ntohl(bp->seqno));
        cpos = cpos + BATMAN_LEN + (6 * bp->num_hna);
      break;

      default:
        printf(" Unknown Packet Type: %d\n", bp->packet_type);
        cpos = packet + len;
      }
    }
  } else {
    printf(" Not a Batman packet: 0x%02X%02X\n", packet[12], packet[13]);
  }
}

struct batman_packet *create_batman_packet(int *len, int first_hop, int direct_link, u_char quality, int seqnr, const u_char *origin, const u_char *from, u_char ttl, u_char hna_count, const u_char *hnas_catted) {
  struct batman_packet *p = malloc(BATMAN_LEN + (hna_count * 6));

  p->packet_type = 0x01;
  p->version = BATMAN_VERSION;
  p->flags = 0;
  if (first_hop) p->flags |= 0x10;
  if (direct_link) p->flags |= 0x40;
  p->tq = quality;
  p->seqno = htonl(seqnr);
  memcpy(&(p->orig), origin, 6);
  memcpy(&(p->prev_sender), from, 6);
  p->ttl = ttl;
  p->num_hna = hna_count;
  p->gw_flags = 0;
  p->align = 0;
  
  memcpy(((u_char *) p) + BATMAN_LEN, hnas_catted, 6 * hna_count);
  *len = BATMAN_LEN + (6 * hna_count);
  
  return p;
}

u_char *create_packet(int *len, const u_char *ethsrc, int first_hop, int direct_link, u_char quality, int seqnr, const u_char *origin, const u_char *from, u_char ttl, u_char hna_count, const u_char *hnas_catted) {
  struct batman_packet *p;
  u_char *pkt;
  int len_p;
  
  p = create_batman_packet(&len_p, first_hop, direct_link, quality, seqnr, origin, from, ttl, hna_count, hnas_catted);
  pkt = malloc(len_p + 14);  //14=Ethernet Header
  
  memcpy(pkt+14, (u_char *) p, len_p);
  memcpy(pkt, BROADCAST, 6);
  memcpy(pkt+6, ethsrc, 6);
  pkt[12] = 0x43;  // Ethernet Type BATMAN
  pkt[13] = 0x05;
  
  *len = len_p + 14;
  
  free(p);
  return pkt;
}

u_char *packet_append(u_char *pkt, int *len, int first_hop, int direct_link, u_char quality, int seqnr, u_char *origin, u_char *from, u_char ttl, u_char hna_count, u_char *hnas_catted) {
  struct batman_packet *p;
  int len_p;
  
  p = create_batman_packet(&len_p, first_hop, direct_link, quality, seqnr, origin, from, ttl, hna_count, hnas_catted);
  pkt = realloc(pkt, *len + len_p);
  
  memcpy(pkt + *len, (u_char *) p, len_p);
  free(p);
  
  *len = *len + len_p;
  return pkt;
}

u_char *create_firsthop_packet(int *len, u_char *src, int seqnr, int hna_count, u_char *hnas) {
  return create_packet(len, src, 1, 0, 255, seqnr, src, src, 50, hna_count, hnas);
}
