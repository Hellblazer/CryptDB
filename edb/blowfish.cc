#include <assert.h>
#include <edb/BasicCrypto.h>
#include <edb/blowfish_data.h>

#include <util/ctr.hh>

/*
 * Based on lib/bf60.c from HiStar.
 */

/*
 *
 * Copyright (C) 1998 David Mazieres (dm@uun.org)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 */

/* This code is derived from a public domain implementation of
 * blowfish found on the net.  I don't remember the original author.
 * By this point, the code has probably been hacked beyond
 * recognition, anyway.  */

static inline uint32_t
bf_F (const bf_ctx *bfc, uint32_t x)
{
  return ((bfc->S[0][x >> 24] + bfc->S[1][x >> 16 & 0xff])
	  ^ bfc->S[2][x >> 8 & 0xff]) + bfc->S[3][x & 0xff];
}

static void __attribute__((unused))
bf_encipher (const bf_ctx *bfc, uint32_t *xl, uint32_t *xr)
{
  uint32_t Xl = *xl;
  uint32_t Xr = *xr;
  int i;

  for (i = 0; i < BF_N;) {
    Xl ^= bfc->P[i++];
    Xr ^= bf_F (bfc, Xl);

    Xr ^= bfc->P[i++];
    Xl ^= bf_F (bfc, Xr);
  }

  *xr = Xl ^ bfc->P[BF_N];
  *xl = Xr ^ bfc->P[BF_N + 1];
}

static void __attribute__((unused))
bf_decipher (const bf_ctx *bfc, uint32_t *xl, uint32_t *xr)
{
  uint32_t Xl = *xl;
  uint32_t Xr = *xr;
  int i;

  for (i = BF_N + 1; i > 1;) {
    Xl ^= bfc->P[i--];
    Xr ^= bf_F (bfc, Xl);

    Xr ^= bfc->P[i--];
    Xl ^= bf_F (bfc, Xr);
  }

  *xr = Xl ^ bfc->P[1];
  *xl = Xr ^ bfc->P[0];
}

static void
bf_initstate (bf_ctx *bfc)
{
  const uint32_t *idp = pihex;
  int i, j;

  /* Load up the initialization data */
  for (i = 0; i < BF_N + 2; ++i)
    bfc->P[i] = *idp++;
  for (i = 0; i < 4; ++i)
    for (j = 0; j < 256; ++j)
      bfc->S[i][j] = *idp++;
}

static void
bf_keysched (bf_ctx *bfc, const void *_key, size_t keybytes)
{
  const uint8_t *key = (const uint8_t *) (_key);
  unsigned i, keypos;
  uint32_t datal, datar;

  if (keybytes > 0)
    for (i = 0, keypos = 0; i < BF_N + 2; ++i) {
      uint32_t data = 0;
      int k;
      for (k = 0; k < 4; ++k) {
	data = (data << 8) | key[keypos++];
	if (keypos >= keybytes)
	  keypos = 0;
      }
      bfc->P[i] ^= data;
    }

  datal = 0;
  datar = 0;

  for (i = 0; i < BF_N + 2; i += 2) {
    bf_encipher (bfc, &datal, &datar);
    bfc->P[i] = datal;
    bfc->P[i + 1] = datar;
  }

  for (i = 0; i < 4; ++i) {
    int j;
    for (j = 0; j < 256; j += 2) {
      bf_encipher (bfc, &datal, &datar);
      bfc->S[i][j] = datal;
      bfc->S[i][j + 1] = datar;
    }
  }
}

static void __attribute__((unused))
bf_setkey (bf_ctx *bfc, const void *key, size_t keybytes)
{
  bf_initstate (bfc);
  bf_keysched (bfc, key, keybytes);
}

static uint64_t __attribute__((unused))
bf60_encipher (bf_ctx *bfc, uint64_t val)
{
  uint32_t Xl = (val >> 30) & 0x3fffffff;
  uint32_t Xr = val & 0x3fffffff;
  int i;

  for (i = 0; i < BF_N;) {
    Xl ^= bfc->P[i++] & 0x3fffffff;
    Xr ^= bf_F (bfc, Xl) & 0x3fffffff;

    Xr ^= bfc->P[i++] & 0x3fffffff;
    Xl ^= bf_F (bfc, Xr) & 0x3fffffff;
  }

  Xl ^= bfc->P[BF_N] & 0x3fffffff;
  Xr ^= bfc->P[BF_N + 1] & 0x3fffffff;
  return (uint64_t) Xr << 30 | Xl;
}

static uint64_t __attribute__((unused))
bf60_decipher (bf_ctx *bfc, uint64_t val)
{
  uint32_t Xl = (val >> 30) & 0x3fffffff;
  uint32_t Xr = val & 0x3fffffff;
  int i;

  for (i = BF_N + 1; i > 1;) {
    Xl ^= bfc->P[i--] & 0x3fffffff;
    Xr ^= bf_F (bfc, Xl) & 0x3fffffff;

    Xr ^= bfc->P[i--] & 0x3fffffff;
    Xl ^= bf_F (bfc, Xr) & 0x3fffffff;
  }

   Xl ^= bfc->P[1] & 0x3fffffff;
   Xr ^= bfc->P[0] & 0x3fffffff;
   return (uint64_t) Xr << 30 | Xl;
}

static uint64_t __attribute__((unused))
bf61_encipher (bf_ctx *bfc, uint64_t val)
{
  uint32_t Xl = (val >> 29) & 0x3fffffff;
  uint32_t Xr = val & 0x7fffffff;
  int i;

  for (i = 0; i < BF_N;) {
    Xl ^= bfc->P[i++] & 0x3fffffff;
    Xr ^= bf_F (bfc, Xl) & 0x7fffffff;

    Xr ^= bfc->P[i++] & 0x7fffffff;
    Xl ^= bf_F (bfc, Xr) & 0x3fffffff;
  }

  Xl ^= bfc->P[BF_N] & 0x3fffffff;
  Xr ^= bfc->P[BF_N + 1] & 0x7fffffff;
  return (uint64_t) Xr << 30 | Xl;
}

static uint64_t __attribute__((unused))
bf61_decipher (bf_ctx *bfc, uint64_t val)
{
  uint32_t Xl = (val >> 30) & 0x7fffffff;
  uint32_t Xr = val & 0x3fffffff;
  int i;

  for (i = BF_N + 1; i > 1;) {
    Xl ^= bfc->P[i--] & 0x7fffffff;
    Xr ^= bf_F (bfc, Xl) & 0x3fffffff;

    Xr ^= bfc->P[i--] & 0x3fffffff;
    Xl ^= bf_F (bfc, Xr) & 0x7fffffff;
  }

   Xl ^= bfc->P[1] & 0x7fffffff;
   Xr ^= bfc->P[0] & 0x3fffffff;
   return (uint64_t) Xr << 31 | Xl;
}

static uint64_t __attribute__((unused))
bf64_encipher (bf_ctx *bfc, uint64_t val) {
  uint32_t Xl = (uint32_t) (val >> 32);
  uint32_t Xr = (uint32_t) val;
  int i;

  for (i = 0; i < BF_N;) {
    Xl ^= bfc->P[i++];
    Xr ^= bf_F (bfc, Xl);

    Xr ^= bfc->P[i++];
    Xl ^= bf_F (bfc, Xr);
  }

  Xl ^= bfc->P[BF_N];
  Xr ^= bfc->P[BF_N + 1];
  return (uint64_t) Xr << 32 | Xl;
}

static uint64_t __attribute__((unused))
bf64_decipher (bf_ctx *bfc, uint64_t val) {
  uint32_t Xl = (uint32_t) (val >> 32);
  uint32_t Xr = (uint32_t) val;
  int i;

  for (i = BF_N + 1; i > 1;) {
    Xl ^= bfc->P[i--];
    Xr ^= bf_F (bfc, Xl);

    Xr ^= bfc->P[i--];
    Xl ^= bf_F (bfc, Xr);
  }

  Xl ^= bfc->P[1];
  Xr ^= bfc->P[0];
  return (uint64_t) Xr << 32 | Xl;
}

uint64_t
blowfish::encrypt(uint64_t v)
{
    uint64_t x;

    // BF_ecb_encrypt((unsigned char *) &v, (unsigned char *) &x, &k, BF_ENCRYPT);
    x = bf60_encipher(&k, v);

    return x;
}

uint64_t
blowfish::decrypt(uint64_t v)
{
    uint64_t x;

    // BF_ecb_encrypt((unsigned char *) &v, (unsigned char *) &x, &k, BF_DECRYPT);
    x = bf60_decipher(&k, v);

    return x;
}

blowfish::blowfish(const string &key)
{
    ANON_REGION(__func__, &perf_cg);

    static std::map<string, bf_ctx> cache;

    auto i = cache.find(key);
    if (i != cache.end()) {
        k = i->second;
    } else {
        // BF_set_key(&k, (int) key.length(), (unsigned char *) key.data());
        bf_setkey(&k, (void *) key.data(), key.length());
        cache[key] = k;
    }
}
