#include "wasuser.h"

#include <time.h>
#include <ctype.h>

/********************************************************* SHA1 *********************************************************/

/* https://gist.github.com/jrabbit/1042021 */
/* https://emn178.github.io/online-tools/sha1.html*/


#include <string.h>

#ifndef WIN32
#include <sys/types.h>
#else
#include <stdint.h>
typedef uint32_t u_int32_t;
#define BYTE_ORDER 1234
#endif

typedef struct
{
   u_int32_t state[5];
   u_int32_t count[2];
   unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64]);
void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const unsigned char* data, u_int32_t len);
void SHA1Final(unsigned char digest[20], SHA1_CTX* context);

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))
#define blk0(i) (block->l[i] = (rol(block->l[i],24)&0xFF00FF00) |(rol(block->l[i],8)&0x00FF00FF))
#define blk(i) (block->l[i&15] = rol(block->l[(i+13)&15]^block->l[(i+8)&15]^block->l[(i+2)&15]^block->l[i&15],1))


/* (R0+R1), R2, R3, R4 are the different operations used in SHA1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);

void SHA1Transform(u_int32_t state[5], const unsigned char buffer[64])
{
   u_int32_t a, b, c, d, e;
   typedef union
   {
      unsigned char c[64];
      u_int32_t l[16];
   } CHAR64LONG16;
#ifdef SHA1HANDSOFF
   CHAR64LONG16 block[1];  /* use array to appear as a pointer */
   memcpy(block, buffer, 64);
#else
   /* The following had better never be used because it causes the
    * pointer-to-const buffer to be cast into a pointer to non-const.
    * And the result is written through.  I threw a "const" in, hoping
    * this will cause a diagnostic.
    */
   CHAR64LONG16* block = (CHAR64LONG16*) buffer;
#endif
   /* Copy context->state[] to working vars */
   a = state[0];
   b = state[1];
   c = state[2];
   d = state[3];
   e = state[4];
   /* 4 rounds of 20 operations each. Loop unrolled. */
   R0(a, b, c, d, e, 0); R0(e, a, b, c, d, 1); R0(d, e, a, b, c, 2); R0(c, d, e, a, b, 3);
   R0(b, c, d, e, a, 4); R0(a, b, c, d, e, 5); R0(e, a, b, c, d, 6); R0(d, e, a, b, c, 7);
   R0(c, d, e, a, b, 8); R0(b, c, d, e, a, 9); R0(a, b, c, d, e, 10); R0(e, a, b, c, d, 11);
   R0(d, e, a, b, c, 12); R0(c, d, e, a, b, 13); R0(b, c, d, e, a, 14); R0(a, b, c, d, e, 15);
   R1(e, a, b, c, d, 16); R1(d, e, a, b, c, 17); R1(c, d, e, a, b, 18); R1(b, c, d, e, a, 19);
   R2(a, b, c, d, e, 20); R2(e, a, b, c, d, 21); R2(d, e, a, b, c, 22); R2(c, d, e, a, b, 23);
   R2(b, c, d, e, a, 24); R2(a, b, c, d, e, 25); R2(e, a, b, c, d, 26); R2(d, e, a, b, c, 27);
   R2(c, d, e, a, b, 28); R2(b, c, d, e, a, 29); R2(a, b, c, d, e, 30); R2(e, a, b, c, d, 31);
   R2(d, e, a, b, c, 32); R2(c, d, e, a, b, 33); R2(b, c, d, e, a, 34); R2(a, b, c, d, e, 35);
   R2(e, a, b, c, d, 36); R2(d, e, a, b, c, 37); R2(c, d, e, a, b, 38); R2(b, c, d, e, a, 39);
   R3(a, b, c, d, e, 40); R3(e, a, b, c, d, 41); R3(d, e, a, b, c, 42); R3(c, d, e, a, b, 43);
   R3(b, c, d, e, a, 44); R3(a, b, c, d, e, 45); R3(e, a, b, c, d, 46); R3(d, e, a, b, c, 47);
   R3(c, d, e, a, b, 48); R3(b, c, d, e, a, 49); R3(a, b, c, d, e, 50); R3(e, a, b, c, d, 51);
   R3(d, e, a, b, c, 52); R3(c, d, e, a, b, 53); R3(b, c, d, e, a, 54); R3(a, b, c, d, e, 55);
   R3(e, a, b, c, d, 56); R3(d, e, a, b, c, 57); R3(c, d, e, a, b, 58); R3(b, c, d, e, a, 59);
   R4(a, b, c, d, e, 60); R4(e, a, b, c, d, 61); R4(d, e, a, b, c, 62); R4(c, d, e, a, b, 63);
   R4(b, c, d, e, a, 64); R4(a, b, c, d, e, 65); R4(e, a, b, c, d, 66); R4(d, e, a, b, c, 67);
   R4(c, d, e, a, b, 68); R4(b, c, d, e, a, 69); R4(a, b, c, d, e, 70); R4(e, a, b, c, d, 71);
   R4(d, e, a, b, c, 72); R4(c, d, e, a, b, 73); R4(b, c, d, e, a, 74); R4(a, b, c, d, e, 75);
   R4(e, a, b, c, d, 76); R4(d, e, a, b, c, 77); R4(c, d, e, a, b, 78); R4(b, c, d, e, a, 79);
   /* Add the working vars back into context.state[] */
   state[0] += a;
   state[1] += b;
   state[2] += c;
   state[3] += d;
   state[4] += e;
   /* Wipe variables */
   a = b = c = d = e = 0;
#ifdef SHA1HANDSOFF
   memset(block, '\0', sizeof(block));
#endif
}

/* SHA1Init - Initialize new context */

void SHA1Init(SHA1_CTX* context)
{
   /* SHA1 initialization constants */
   context->state[0] = 0x67452301;
   context->state[1] = 0xEFCDAB89;
   context->state[2] = 0x98BADCFE;
   context->state[3] = 0x10325476;
   context->state[4] = 0xC3D2E1F0;
   context->count[0] = context->count[1] = 0;
}


/* Run your data through this. */

void SHA1Update(SHA1_CTX* context, const unsigned char* data, u_int32_t len)
{
   u_int32_t i;
   u_int32_t j;

   j = context->count[0];
   if ((context->count[0] += len << 3) < j)
      context->count[1]++;
   context->count[1] += (len >> 29);
   j = (j >> 3) & 63;
   if ((j + len) > 63)
   {
      memcpy(&context->buffer[j], data, (i = 64 - j));
      SHA1Transform(context->state, context->buffer);
      for (; i + 63 < len; i += 64)
      {
         SHA1Transform(context->state, &data[i]);
      }
      j = 0;
   }
   else i = 0;
   memcpy(&context->buffer[j], &data[i], len - i);
}


/* Add padding and return the message digest. */

void SHA1Final(unsigned char digest[20], SHA1_CTX* context)
{
   unsigned i;
   unsigned char finalcount[8];
   unsigned char c;

#if 0	/* untested "improvement" by DHR */
   /* Convert context->count to a sequence of bytes
    * in finalcount.  Second element first, but
    * big-endian order within element.
    * But we do it all backwards.
    */
   unsigned char* fcp = &finalcount[8];

   for (i = 0; i < 2; i++)
   {
      u_int32_t t = context->count[i];
      int j;

      for (j = 0; j < 4; t >>= 8, j++)
         *--fcp = (unsigned char) t
   }
#else
   for (i = 0; i < 8; i++)
   {
      finalcount[i] = (unsigned char) ((context->count[(i >= 4 ? 0 : 1)]
         >> ((3 - (i & 3)) * 8)) & 255);  /* Endian independent */
   }
#endif
   c = 0200;
   SHA1Update(context, &c, 1);
   while ((context->count[0] & 504) != 448)
   {
      c = 0000;
      SHA1Update(context, &c, 1);
   }
   SHA1Update(context, finalcount, 8);  /* Should cause a SHA1Transform() */
   for (i = 0; i < 20; i++)
   {
      digest[i] = (unsigned char)
         ((context->state[i >> 2] >> ((3 - (i & 3)) * 8)) & 255);
   }
   /* Wipe variables */
   memset(context, '\0', sizeof(*context));
   memset(&finalcount, '\0', sizeof(finalcount));
}

void sha1(const unsigned char* buffer, u_int32_t len, unsigned char digest[20])
{
   SHA1_CTX ctx;
   SHA1Init(&ctx);
   SHA1Update(&ctx, buffer, len);
   SHA1Final(digest, &ctx);
}

/********************************************************* SHA1 *********************************************************/

/********************************************************* 3DES ECB *********************************************************/

/* https://rosettacode.org/wiki/Data_Encryption_Standard#C */
/* http://tripledes.online-domain-tools.com/ */

#include <stdlib.h>
#include <string.h>

typedef unsigned char ubyte;

#define KEY_LEN 8
typedef ubyte keydes_t[KEY_LEN];

const static ubyte PC1[] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

const static ubyte PC2[] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

const static ubyte IP[] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

const static ubyte E[] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

const static ubyte S[][64] = {
    {
        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
         0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
         4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
        15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
    },
    {
        15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
         3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
         0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
        13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
    },
    {
        10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
        13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
        13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
         1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
    },
    {
         7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
        13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
        10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
         3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
    },
    {
         2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
        14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
         4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
        11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
    },
    {
        12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
        10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
         9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
         4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
    },
    {
         4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
        13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
         1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
         6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
    },
    {
        13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
         1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
         7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
         2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
    }
};

const static ubyte P[] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

const static ubyte IP2[] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

const static ubyte SHIFTS[] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

typedef struct
{
   ubyte* data;
   int len;
} des_string;

/*
 * Gets the value of a bit in an array of bytes
 *
 * src: the array of bytes to index
 * index: the desired bit to test the value of
 *
 * returns: the bit at the specified position in the array
 */
static int peekBit(const ubyte* src, int index)
{
   int cell = index / 8;
   int bit = 7 - index % 8;
   return (src[cell] & (1 << bit)) != 0;
}

/*
 * Sets the value of a bit in an array of bytes
 *
 * dst: the array of bits to set a bit in
 * index: the position of the bit to set
 * value: the value for the bit to set
 */
static void pokeBit(ubyte* dst, int index, int value)
{
   int cell = index / 8;
   int bit = 7 - index % 8;
   if (value == 0)
   {
      dst[cell] &= ~(1 << bit);
   }
   else
   {
      dst[cell] |= (1 << bit);
   }
}

/*
 * Transforms one array of bytes by shifting the bits the specified number of positions
 *
 * src: the array to shift bits from
 * len: the length of the src array
 * times: the number of positions that the bits should be shifted
 * dst: a bytes array allocated by the caller to store the shifted values
 */
static void shiftLeft(const ubyte* src, int len, int times, ubyte* dst)
{
   int i, t;
   for (i = 0; i <= len; ++i)
   {
      pokeBit(dst, i, peekBit(src, i));
   }
   for (t = 1; t <= times; ++t)
   {
      int temp = peekBit(dst, 0);
      for (i = 1; i <= len; ++i)
      {
         pokeBit(dst, i - 1, peekBit(dst, i));
      }
      pokeBit(dst, len - 1, temp);
   }
}

/*
 * Calculates the sub keys to be used in processing the messages
 *
 * key: the array of bytes representing the key
 * ks: the subkeys that have been allocated by the caller
 */
typedef ubyte subkey_t[17][6]; /* 17 sets of 48 bits */
static void getSubKeys(const keydes_t key, subkey_t ks)
{
   ubyte c[17][7];  /* 56 bits */
   ubyte d[17][4];  /* 28 bits */
   ubyte kp[7];
   int i, j;

   /* intialize */
   memset(c, 0, sizeof(c));
   memset(d, 0, sizeof(d));
   memset(ks, 0, sizeof(subkey_t));

   /* permute 'key' using table PC1 */
   for (i = 0; i < 56; ++i)
   {
      pokeBit(kp, i, peekBit(key, PC1[i] - 1));
   }

   /* split 'kp' in half and process the resulting series of 'c' and 'd' */
   for (i = 0; i < 28; ++i)
   {
      pokeBit(c[0], i, peekBit(kp, i));
      pokeBit(d[0], i, peekBit(kp, i + 28));
   }

   /* shift the components of c and d */
   for (i = 1; i < 17; ++i)
   {
      shiftLeft(c[i - 1], 28, SHIFTS[i - 1], c[i]);
      shiftLeft(d[i - 1], 28, SHIFTS[i - 1], d[i]);
   }

   /* merge 'd' into 'c' */
   for (i = 1; i < 17; ++i)
   {
      for (j = 28; j < 56; ++j)
      {
         pokeBit(c[i], j, peekBit(d[i], j - 28));
      }
   }

   /* form the sub-keys and store them in 'ks'
    * permute 'c' using table PC2 */
   for (i = 1; i < 17; ++i)
   {
      for (j = 0; j < 48; ++j)
      {
         pokeBit(ks[i], j, peekBit(c[i], PC2[j] - 1));
      }
   }
}

/*
 * Function used in processing the messages
 *
 * r: an array of bytes to be processed
 * ks: one of the subkeys to be used for processing
 * sp: output from the processing
 */
static void f(ubyte* r, ubyte* ks, ubyte* sp)
{
   ubyte er[6]; /* 48 bits */
   ubyte sr[4]; /* 32 bits */
   int i;

   /* initialize */
   memset(er, 0, sizeof(er));
   memset(sr, 0, sizeof(sr));

   /* permute 'r' using table E */
   for (i = 0; i < 48; ++i)
   {
      pokeBit(er, i, peekBit(r, E[i] - 1));
   }

   /* xor 'er' with 'ks' and store back into 'er' */
   for (i = 0; i < 6; ++i)
   {
      er[i] ^= ks[i];
   }

   /* process 'er' six bits at a time and store resulting four bits in 'sr' */
   for (i = 0; i < 8; ++i)
   {
      int j = i * 6;
      int b[6];
      int k, row, col, m, n;

      for (k = 0; k < 6; ++k)
      {
         b[k] = peekBit(er, j + k) != 0 ? 1 : 0;
      }

      row = 2 * b[0] + b[5];
      col = 8 * b[1] + 4 * b[2] + 2 * b[3] + b[4];
      m = S[i][row * 16 + col]; /* apply table s */
      n = 1;

      while (m > 0)
      {
         int p = m % 2;
         pokeBit(sr, (i + 1) * 4 - n, p == 1);
         m /= 2;
         n++;
      }
   }

   /* permute sr using table P */
   for (i = 0; i < 32; ++i)
   {
      pokeBit(sp, i, peekBit(sr, P[i] - 1));
   }
}

/*
 * Processing of block of the message
 *
 * message: an 8 byte block from the message
 * ks: the subkeys to use in processing
 * ep: space for an encoded 8 byte block allocated by the caller
 */
static void processMessage(const ubyte* message, subkey_t ks, ubyte* ep)
{
   ubyte left[17][4];  /* 32 bits */
   ubyte right[17][4]; /* 32 bits */
   ubyte mp[8];        /* 64 bits */
   ubyte e[8];         /* 64 bits */
   int i, j;

   /* permute 'message' using table IP */
   for (i = 0; i < 64; ++i)
   {
      pokeBit(mp, i, peekBit(message, IP[i] - 1));
   }

   /* split 'mp' in half and process the resulting series of 'l' and 'r */
   for (i = 0; i < 32; ++i)
   {
      pokeBit(left[0], i, peekBit(mp, i));
      pokeBit(right[0], i, peekBit(mp, i + 32));
   }
   for (i = 1; i < 17; ++i)
   {
      ubyte fs[4]; /* 32 bits */

      memcpy(left[i], right[i - 1], 4);
      f(right[i - 1], ks[i], fs);
      for (j = 0; j < 4; ++j)
      {
         left[i - 1][j] ^= fs[j];
      }
      memcpy(right[i], left[i - 1], 4);
   }

   /* amalgamate r[16] and l[16] (in that order) into 'e' */
   for (i = 0; i < 32; ++i)
   {
      pokeBit(e, i, peekBit(right[16], i));
   }
   for (i = 32; i < 64; ++i)
   {
      pokeBit(e, i, peekBit(left[16], i - 32));
   }

   /* permute 'e' using table IP2 ad return result as a hex string */
   for (i = 0; i < 64; ++i)
   {
      pokeBit(ep, i, peekBit(e, IP2[i] - 1));
   }
}

/*
 * Encrypts a message using DES
 *
 * key: the key to use to encrypt the message
 * message: the message to be encrypted
 * len: the length of the message
 * pad: 1 = apply padding, do not apply padding
 *
 * returns: a paring of dynamically allocated memory for the encoded message,
 *          and the length of the encoded message.
 *          the caller will need to free the memory after use.
 */
des_string des_encrypt(const keydes_t key, const ubyte* message, int len, int pad)
{
   des_string result = { 0, 0 };
   subkey_t ks;
   ubyte padByte;
   int i;

   getSubKeys(key, ks);

   if (pad == 1)
   {
      padByte = 8 - len % 8;
      result.len = len + padByte;
      result.data = (ubyte*) malloc(result.len);
      memcpy(result.data, message, len);
      memset(&result.data[len], padByte, padByte);
   }
   else
      if (pad == 0)
      {
         result.len = len;
         result.data = (ubyte*) malloc(result.len);
         memcpy(result.data, message, len);
      }

   for (i = 0; i < result.len; i += 8)
   {
      processMessage(&result.data[i], ks, &result.data[i]);
   }

   return result;
}

/*
 * Decrypts a message using DES
 *
 * key: the key to use to decrypt the message
 * message: the message to be decrypted
 * len: the length of the message
 * pad: 1 = apply padding, do not apply padding
 *
 * returns: a paring of dynamically allocated memory for the decoded message,
 *          and the length of the decoded message.
 *          the caller will need to free the memory after use.
 */
des_string des_decrypt(const keydes_t key, const ubyte* message, int len, int pad)
{
   des_string result = { 0, 0 };
   subkey_t ks;
   int i, j;
   ubyte padByte;

   getSubKeys(key, ks);
   /* reverse the subkeys */
   for (i = 1; i < 9; ++i)
   {
      for (j = 0; j < 6; ++j)
      {
         ubyte temp = ks[i][j];
         ks[i][j] = ks[17 - i][j];
         ks[17 - i][j] = temp;
      }
   }

   result.data = (ubyte*) malloc(len);
   memcpy(result.data, message, len);
   result.len = len;
   for (i = 0; i < result.len; i += 8)
   {
      processMessage(&result.data[i], ks, &result.data[i]);
   }

   if (pad == 1)
   {
      padByte = result.data[len - 1];
      if (padByte <= 8) result.len -= padByte;
   }

   return result;
}

des_string tripledesdecrypt(unsigned char key[24], unsigned char* input, int len)
{
   des_string empty = { 0, 0 };
   if (len % 8) return empty;

   keydes_t des_key;
   memcpy(des_key, key + 16, 8);
   des_string phase1 = des_decrypt(des_key, input, len, 0);
   if (phase1.len == 0) return empty;
   memcpy(des_key, key + 8, 8);
   des_string phase2 = des_encrypt(des_key, phase1.data, phase1.len, 0);
   if (phase2.len == 0) return empty;
   memcpy(des_key, key, 8);
   des_string phase3 = des_decrypt(des_key, phase2.data, phase2.len, 1);
   free(phase1.data);
   free(phase2.data);
   return phase3;
}

/********************************************************* 3DES ECB *********************************************************/

/********************************************************* BASE64 *********************************************************/

/* https://cryptii.com/pipes/base64-to-hex */

const unsigned char * base = (const unsigned char *) "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int basepos(char c, const unsigned char* base)
{
   const unsigned char * t = (unsigned char *) strchr((const char *) base, c);
   return t - base;
}

typedef struct
{
   unsigned char* data;
   int len;
} base64_string;

base64_string base64decode(unsigned char* input, int len)
{
   int skip = 0;
   base64_string decoded = { 0, 0 };

   if (len % 4) return decoded;

   while (input[len - 1 - skip] == '=') ++skip;
   decoded.len = skip ? (((len - skip) / 4) * 3) + 3 - skip : len / 4 * 3;
   decoded.data = (unsigned char*) malloc(decoded.len);

   for (int i = 0; i < (len - skip); ++i) if (!strchr((const char *) base, input[i])) return decoded;

   for (int i = 0; i < (len - skip) / 4; ++i)
   {
      int p0 = basepos(input[i * 4], base);
      int p1 = basepos(input[i * 4 + 1], base);
      int p2 = basepos(input[i * 4 + 2], base);
      int p3 = basepos(input[i * 4 + 3], base);
      unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);
      unsigned char b2 = ((p1 & 15) << 4) + ((p2 & 60) >> 2);
      unsigned char b3 = ((p2 & 3) << 6) + p3;
      decoded.data[i * 3] = b1;
      decoded.data[i * 3 + 1] = b2;
      decoded.data[i * 3 + 2] = b3;
   }

   if (skip == 1)
   {
      int p0 = basepos(input[len - 4], base);
      int p1 = basepos(input[len - 3], base);
      int p2 = basepos(input[len - 2], base);
      unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);
      unsigned char b2 = ((p1 & 15) << 4) + ((p2 & 60) >> 2);
      decoded.data[decoded.len - 2] = b1;
      decoded.data[decoded.len - 1] = b2;
   }
   else
      if (skip == 2)
      {
         int p0 = basepos(input[len - 4], base);
         int p1 = basepos(input[len - 3], base);
         unsigned char b1 = (p0 << 2) + ((p1 & 48) >> 4);
         decoded.data[decoded.len - 1] = b1;
      }

   return decoded;
}

/********************************************************* BASE64 *********************************************************/

/********************************************************* AES128 ECB *********************************************************/

/* https://github.com/kokke/tiny-AES-c */
/* http://aes.online-domain-tools.com/ */

#include <stdint.h>
#include <string.h>

#define AES128 1
#define AES_BLOCKLEN 16 //Block length in bytes AES is 128b block only

#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176

struct AES_ctx
{
   uint8_t RoundKey[AES_keyExpSize];
   uint8_t Iv[AES_BLOCKLEN];
};

#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.

// jcallan@github points out that declaring Multiply as a function 
// reduces code size considerably with the Keil ARM compiler.
// See this link for more information: https://github.com/kokke/tiny-AES-C/pull/3
#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

typedef uint8_t state_t[4][4];

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
   //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

#define getSBoxValue(num) (sbox[(num)])
#define getSBoxInvert(num) (rsbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
   unsigned i, j, k;
   uint8_t tempa[4]; // Used for the column/row operations

   // The first round key is the key itself.
   for (i = 0; i < Nk; ++i)
   {
      RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
      RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
      RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
      RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
   }

   // All other round keys are found from the previous round keys.
   for (i = Nk; i < Nb * (Nr + 1); ++i)
   {
      {
         k = (i - 1) * 4;
         tempa[0] = RoundKey[k + 0];
         tempa[1] = RoundKey[k + 1];
         tempa[2] = RoundKey[k + 2];
         tempa[3] = RoundKey[k + 3];

      }

      if (i % Nk == 0)
      {
         // This function shifts the 4 bytes in a word to the left once.
         // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

         // Function RotWord()
         {
            const uint8_t u8tmp = tempa[0];
            tempa[0] = tempa[1];
            tempa[1] = tempa[2];
            tempa[2] = tempa[3];
            tempa[3] = u8tmp;
         }

         // SubWord() is a function that takes a four-byte input word and 
         // applies the S-box to each of the four bytes to produce an output word.

         // Function Subword()
         {
            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);
         }

         tempa[0] = tempa[0] ^ Rcon[i / Nk];
      }

      j = i * 4; k = (i - Nk) * 4;
      RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
      RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
      RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
      RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
   }
}

void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key)
{
   memcpy(ctx->Iv, key, AES_BLOCKLEN);
   KeyExpansion(ctx->RoundKey, key);
}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
   uint8_t i, j;
   for (i = 0; i < 4; ++i)
   {
      for (j = 0; j < 4; ++j)
      {
         (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
      }
   }
}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state)
{
   uint8_t i, j;
   for (i = 0; i < 4; ++i)
   {
      for (j = 0; j < 4; ++j)
      {
         (*state)[j][i] = getSBoxValue((*state)[j][i]);
      }
   }
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state)
{
   uint8_t temp;

   // Rotate first row 1 columns to left  
   temp = (*state)[0][1];
   (*state)[0][1] = (*state)[1][1];
   (*state)[1][1] = (*state)[2][1];
   (*state)[2][1] = (*state)[3][1];
   (*state)[3][1] = temp;

   // Rotate second row 2 columns to left  
   temp = (*state)[0][2];
   (*state)[0][2] = (*state)[2][2];
   (*state)[2][2] = temp;

   temp = (*state)[1][2];
   (*state)[1][2] = (*state)[3][2];
   (*state)[3][2] = temp;

   // Rotate third row 3 columns to left
   temp = (*state)[0][3];
   (*state)[0][3] = (*state)[3][3];
   (*state)[3][3] = (*state)[2][3];
   (*state)[2][3] = (*state)[1][3];
   (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
   return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state)
{
   uint8_t i;
   uint8_t Tmp, Tm, t;
   for (i = 0; i < 4; ++i)
   {
      t = (*state)[i][0];
      Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
      Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp;
      Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp;
      Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp;
      Tm = (*state)[i][3] ^ t;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp;
   }
}

// Multiply is used to multiply numbers in the field GF(2^8)
// Note: The last call to xtime() is unneeded, but often ends up generating a smaller binary
//       The compiler seems to be able to vectorize the operation better this way.
//       See https://github.com/kokke/tiny-AES-c/pull/34
#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
   return (((y & 1) * x) ^
      ((y >> 1 & 1)* xtime(x)) ^
      ((y >> 2 & 1)* xtime(xtime(x))) ^
      ((y >> 3 & 1)* xtime(xtime(xtime(x)))) ^
      ((y >> 4 & 1)* xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
}
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

#endif

// MixColumns function mixes the columns of the state matrix.
// The method used to multiply may be difficult to understand for the inexperienced.
// Please use the references to gain more information.
static void InvMixColumns(state_t* state)
{
   int i;
   uint8_t a, b, c, d;
   for (i = 0; i < 4; ++i)
   {
      a = (*state)[i][0];
      b = (*state)[i][1];
      c = (*state)[i][2];
      d = (*state)[i][3];

      (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
      (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
      (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
      (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
   }
}


// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void InvSubBytes(state_t* state)
{
   uint8_t i, j;
   for (i = 0; i < 4; ++i)
   {
      for (j = 0; j < 4; ++j)
      {
         (*state)[j][i] = getSBoxInvert((*state)[j][i]);
      }
   }
}

static void InvShiftRows(state_t* state)
{
   uint8_t temp;

   // Rotate first row 1 columns to right  
   temp = (*state)[3][1];
   (*state)[3][1] = (*state)[2][1];
   (*state)[2][1] = (*state)[1][1];
   (*state)[1][1] = (*state)[0][1];
   (*state)[0][1] = temp;

   // Rotate second row 2 columns to right 
   temp = (*state)[0][2];
   (*state)[0][2] = (*state)[2][2];
   (*state)[2][2] = temp;

   temp = (*state)[1][2];
   (*state)[1][2] = (*state)[3][2];
   (*state)[3][2] = temp;

   // Rotate third row 3 columns to right
   temp = (*state)[0][3];
   (*state)[0][3] = (*state)[1][3];
   (*state)[1][3] = (*state)[2][3];
   (*state)[2][3] = (*state)[3][3];
   (*state)[3][3] = temp;
}

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
   uint8_t round = 0;

   // Add the First round key to the state before starting the rounds.
   AddRoundKey(0, state, RoundKey);

   // There will be Nr rounds.
   // The first Nr-1 rounds are identical.
   // These Nr rounds are executed in the loop below.
   // Last one without MixColumns()
   for (round = 1; ; ++round)
   {
      SubBytes(state);
      ShiftRows(state);
      if (round == Nr)
      {
         break;
      }
      MixColumns(state);
      AddRoundKey(round, state, RoundKey);
   }
   // Add round key to last round
   AddRoundKey(Nr, state, RoundKey);
}

static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
   uint8_t round = 0;

   // Add the First round key to the state before starting the rounds.
   AddRoundKey(Nr, state, RoundKey);

   // There will be Nr rounds.
   // The first Nr-1 rounds are identical.
   // These Nr rounds are executed in the loop below.
   // Last one without InvMixColumn()
   for (round = (Nr - 1); ; --round)
   {
      InvShiftRows(state);
      InvSubBytes(state);
      AddRoundKey(round, state, RoundKey);
      if (round == 0)
      {
         break;
      }
      InvMixColumns(state);
   }

}

/*****************************************************************************/
/* Public functions:                                                         */
/*****************************************************************************/
static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
   uint8_t i;
   for (i = 0; i < AES_BLOCKLEN; ++i) // The block in AES is always 128bit no matter the key size
   {
      buf[i] ^= Iv[i];
   }
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
   uintptr_t i;
   uint8_t* Iv = ctx->Iv;
   for (i = 0; i < length; i += AES_BLOCKLEN)
   {
      XorWithIv(buf, Iv);
      Cipher((state_t*) buf, ctx->RoundKey);
      Iv = buf;
      buf += AES_BLOCKLEN;
   }
   /* store Iv in ctx for next call */
   memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, uint32_t length)
{
   uintptr_t i;
   uint8_t storeNextIv[AES_BLOCKLEN];
   for (i = 0; i < length; i += AES_BLOCKLEN)
   {
      memcpy(storeNextIv, buf, AES_BLOCKLEN);
      InvCipher((state_t*) buf, ctx->RoundKey);
      XorWithIv(buf, ctx->Iv);
      memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
      buf += AES_BLOCKLEN;
   }
}

/********************************************************* AES128 ECB *********************************************************/

/*
* password: LTPA Keys Password
* tripledeskey: LTPA 3DES Key
* ltpakey: LTPA AES Key (Output)
* return: 0 = OK, 1 = LTPA 3DES Key not valid
*/
int prepareltpakey(unsigned char *password, unsigned char *tripledeskey, ltpakey_t *ltpakey)
{
   unsigned char des_key[24];
   sha1(password, strlen((const char *) password), des_key);
   memset(des_key + 20, 0x0, 4);
   base64_string tripledes = base64decode(tripledeskey, strlen((const char *) tripledeskey));
   if (tripledes.len == 0) return 1;
   des_string aes_key = tripledesdecrypt(des_key, tripledes.data, tripledes.len);
   free(tripledes.data);
   if (aes_key.len == 0 || aes_key.len < 16) return 2;
   memcpy(*ltpakey, aes_key.data, 16);
   free(aes_key.data);
   return 0;
}

/*
* ltpatoken: LTPA Token
* ltpakey: LTPA AES Key
* ltpadata: LTPA Decoded (Output)
* return: 0 = OK, 1 = LTPA Token not valid
*/
int ltpadecode(const unsigned char *ltpatoken, ltpakey_t ltpakey, ltpa_t *ltpadata)
{
   base64_string ltpa = base64decode((unsigned char *) ltpatoken, strlen((const char *) ltpatoken));
   if (ltpa.len == 0) return 1;

   struct AES_ctx aes_ctx;
   AES_init_ctx_iv(&aes_ctx, ltpakey);
   AES_CBC_decrypt_buffer(&aes_ctx, ltpa.data, ltpa.len);

   unsigned char pad = ltpa.data[ltpa.len - 1];

   if (pad > 16)
   {
      free(ltpa.data);
      return 1;
   }

   ltpa.len -= pad;
   ltpa.data[ltpa.len] = 0;

   for (int i = 0; i < ltpa.len - 1; ++i)
   {
      if (iscntrl(ltpa.data[i]))
      {
         free(ltpa.data);
         return 1;
      }
   }

   ltpa.data[ltpa.len - 1] = 0;

   byte_p pos = ltpa.data;
   ltpadata->length = 0;
   for (int i = 0; i < MAX_ATTRIBUTES; ++i)
   {
      byte_p ea = (unsigned char *) strchr((const char *) pos, ':');
      if (ea == 0) break;
      *ea = 0;
      byte_p ev = (unsigned char *) strchr((const char *) ++ea, '$');
      if (ev == 0) ev = (unsigned char *) strchr((const char *) ea, '%');
      if (ev == 0) break;
      *ev = 0;

      ltpadata->attrs[i] = (byte_p) malloc(strlen((const char *) pos) + 1);
      strcpy((char *) ltpadata->attrs[i], (const char *) pos);
      ltpadata->values[i] = (byte_p) malloc(strlen((const char *) ea) + 1);
      strcpy((char *) ltpadata->values[i], (const char *) ea);

      ++ltpadata->length;
      pos = ev + 1;
   }

   free(ltpa.data);
   return 0;
}

/*
* ltpa: LTPA Decoded
*/
void ltparelease(ltpa_t* ltpa)
{
   for (int i = 0; i < ltpa->length; ++i)
   {
      free(ltpa->attrs[i]);
      free(ltpa->values[i]);
   }

   ltpa->length = 0;
}
