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

#include "mac_storage.h"

typedef unsigned char u_char;

u_char * store = NULL;
unsigned long storesize = 0;

int store_has(const u_char *addr) {
  unsigned long i;
  
  if (!store) return 0;
  
  for (i=0; i<storesize; i+=6) {
    if (! memcmp(store + i, addr, 6)) return 1;
  }
  
  return 0;
}

const u_char *store_get_random() {
  unsigned long entrycount, rnd;
  
  if (!store) return NULL;

  entrycount = storesize / 6;
  rnd = random() % entrycount;
  
  return (store + (rnd * 6));
}

void store_add(const u_char *addr) {
  if (store_has(addr)) return;  //Skip duplicates
  
  store = realloc(store, storesize + 6);
  memcpy(store + storesize, addr, 6);
  storesize += 6;
}

const u_char *store_get_all(unsigned long *length) {
  *length = storesize;
  return store;
}
