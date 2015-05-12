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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/ether.h>

#include "packets.h"
#include "node.h"
#include "tests.h"

u_char defaulthna[6] = "\x00\x33\x11\x33\x33\x77";

u_char *get_interface_mac(char *iface) {
  static struct ifreq ifr1;
  bzero(&ifr1, sizeof(ifr1));
  struct ether_addr* mac;
  u_char *ea = malloc(6);
  
  int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock_fd == -1) {
    printf("Couldn't open socket on interface\n");
    exit(-1);
  }
  strcpy(ifr1.ifr_name, iface);
  if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr1) == -1) {
    printf("Couldn't execute ioctl on interface\n");
    exit(-1);
  }
  close(sock_fd);

  mac = (struct ether_addr *) ifr1.ifr_hwaddr.sa_data;
  memcpy(ea, mac->ether_addr_octet, 6);
  
  return ea;
}

pcap_t *open_sniffer(char *dev) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;

  handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
  if (handle == NULL) {
  fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(-1);
  }

  return handle;
}

void usage_and_die(char *binary, char *message) {
  fprintf(stderr, "  - - = = # #   T H E   J O K E R   # # = = - -  \n");
  fprintf(stderr, "           B.A.T.M.A.N.'s arch nemesis\n\n");
  fprintf(stderr, "Usage: %s -i <interface> [other options]\n\n", binary);
  fprintf(stderr, "GENERAL OPTIONS:\n");
  fprintf(stderr, "-i <interface>\n");
  fprintf(stderr, "   Select the Interface that is connected to the BATMAN network\n");
  fprintf(stderr, "-m <mac-addr>\n");
  fprintf(stderr, "   Use this MAC Address instead of your real one (Format: 00:11:22:33:44:55)\n");
  fprintf(stderr, "-h <mac-addr>\n");
  fprintf(stderr, "   Use this HNA Address instead of the default one (00:33:11:33:33:77)\n");
  fprintf(stderr, "-r <mac-addr>\n");
  fprintf(stderr, "   (Blackhole only) Make this neighbor responsible for the black hole.\n");
  fprintf(stderr, "   (Current BATMAN version filters non-broadcasts messages and this doesn't work!)\n");
  fprintf(stderr, "-t <time>\n");
  fprintf(stderr, "   (Loop) Specify the waiting time between each packet in milliseconds.\n");
  fprintf(stderr, "   (Fuzz) Specify the time to sniff for available MAC addresses in seconds.\n");
  fprintf(stderr, "-v\n");
  fprintf(stderr, "   (Flood) Use STA flooding instead of route flooding\n");
  fprintf(stderr, "   (Fuzz) If given a mutation-based fuzzing is executed (otherwise random packets)\n");
  fprintf(stderr, "\nPENETRATION TESTS:\n");
  fprintf(stderr, "-f\n");
  fprintf(stderr, "   Starts a Flooding penetration test. First a fake node is announced in the network, and after 30 seconds,\n");
  fprintf(stderr, "   huge amounts of random Routes and HNAs via this node are published.\n");
  fprintf(stderr, "   If -v is specified, new Ad-Hoc Stations are created. Both tests may lead to memory exhaustion\n");
  fprintf(stderr, "   and bandwidth consumption in the whole network. WARNING: This includes crashes and lockups!\n");
  fprintf(stderr, "-l\n");
  fprintf(stderr, "   Tries to create loops. In this mode The Joker listens if a node forwards an incoming 3 or more\n");
  fprintf(stderr, "   hop route, and its predecessor will be told the destination can be reached directly over the\n");
  fprintf(stderr, "   forwarding node. This creates Loops and lets incoming packets time out due to TTL becoming 0.\n");
  fprintf(stderr, "   This test is rather unstable and possibly needs tweaking with -t (Default: 500 ms)\n");
  fprintf(stderr, "-b\n");
  fprintf(stderr, "   Creates a black hole. Use -r to make some neighbor responsible by only forwarding the fake\n");
  fprintf(stderr, "   routes to it instead of broadcasting. (-r does not work, BATMAN filters those packets.)\n");
  fprintf(stderr, "-z\n");
  fprintf(stderr, "   Start a random fuzzing test after sniffing for available MAC addresses.\n");
  fprintf(stderr, "   Either run a standard fuzzing, where joker collects Target addresses for -t seconds,\n");
  fprintf(stderr, "   Or run a mutation-based fuzzing test using incoming packets with -v\n");

  fprintf(stderr, "\n");
  
  if (message) fprintf(stderr, "\n%s\n", message);
  exit(-1);
}

int main(int argc, char *argv[]) {
  pcap_t *sniffer;
  u_char *ifmac = NULL, *hna = defaulthna, *res = (u_char *) BROADCAST;
  char *ifname = NULL;
  int opt;
  int sniff_time = -1;
  int test_version = 0;
  char test = '0';

  srandom(time(NULL));

  while ((opt = getopt(argc, argv, "i:m:h:r:t:vflbz")) != -1) {
    switch (opt) {
    case 'i':
      ifname = optarg;
    break;
    case 'm':
      ifmac = malloc(6);
      sscanf(optarg, "%X:%X:%X:%X:%X:%X", (unsigned int *) &ifmac[0], (unsigned int *) &ifmac[1], (unsigned int *) &ifmac[2], (unsigned int *) &ifmac[3], (unsigned int *) &ifmac[4], (unsigned int *) &ifmac[5]);
    break;
    case 'h':
      hna = malloc(6);
      sscanf(optarg, "%X:%X:%X:%X:%X:%X", (unsigned int *) &hna[0], (unsigned int *) &hna[1], (unsigned int *) &hna[2], (unsigned int *) &hna[3], (unsigned int *) &hna[4], (unsigned int *) &hna[5]);
    break;
    case 'r':
      res = malloc(6);
      sscanf(optarg, "%X:%X:%X:%X:%X:%X", (unsigned int *) &res[0], (unsigned int *) &res[1], (unsigned int *) &res[2], (unsigned int *) &res[3], (unsigned int *) &res[4], (unsigned int *) &res[5]);
    break;
    case 't':
    	sniff_time = atoi(optarg);
    break;
    case 'v':
    	test_version = 2;
    break;
    case 'f':
    case 'b':
    case 'z':
    case 'l':
      test = opt;
    break;

    default: /* '?' */
      usage_and_die(argv[0], NULL);
    }
  }
  
  if (! ifname) {
    usage_and_die(argv[0], "Interface name missing.");
  }

  if (! sniff_time) {
	  usage_and_die(argv[0], "Time missing.");
  }

  if (!ifmac) {
    ifmac = get_interface_mac(ifname);
    printf("Using real MAC address "); print_mac(ifmac);
  } else {
    printf("Using fake MAC address "); print_mac(ifmac);
  }
  printf("\nUsing HNA address "); print_mac(hna); printf("\n");

  switch (test) {
    case 'f':
      sniffer = open_sniffer(ifname);
      if(test_version == 2) {
	printf("\nSTA Flooding\n");
	sniff_reinject_bpackets(sniffer, ifmac, 2);
      } else {
	printf("\nRoute Flooding\n");
	start_fake_node(sniffer, ifmac, 1, hna, (u_char *) BROADCAST);
	printf("Broadcasting fake Client for 30 secs before flooding...\n");
	sleep(30);
	printf("GO GO GO!\n");
	fake_indirect_nodes(sniffer, ifmac, 0);
      }
    break;
    case 'l':
      if (sniff_time == -1) sniff_time = 10;
      printf("\n Loop Forming\n");
      sniffer = open_sniffer(ifname);
      create_loops(sniffer, sniff_time);
    break;
    case 'z':
      if (sniff_time == -1) sniff_time = 10;
	if(test_version == 2){
	  printf("\n Mutation mode applied\n");
	  sniffer = open_sniffer(ifname);
	  sniff_reinject_bpackets(sniffer, ifmac, 1);
	} else {
	  printf("\n Random mode applied\n");
	  sniffer = open_sniffer(ifname);
	  rfuzz_batman(sniffer, sniff_time, ifmac);
	}
    break;
    case 'b':
        printf("\n Blackhole\n");
        sniffer = open_sniffer(ifname);
        start_fake_node(sniffer, ifmac, 1, hna, res);
        while(1);
    break;
    default:
      usage_and_die(argv[0], "No pen test selected!");
  }
  return 0;
}
