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

#include <pcap.h>

void fake_indirect_nodes(pcap_t *inject_here, u_char *localmac, int usleepinterval);
void create_loops(pcap_t *inject_here, int time_tweak);
void rfuzz_batman(pcap_t *pcap_handle, int sniff_time, u_char *ifmac);
void sniff_reinject_bpackets(pcap_t *pcap_handle, u_char *ifmac, int test);
