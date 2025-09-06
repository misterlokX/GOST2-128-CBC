/* 
 * GOST2-128 File Encryptor/Decryptor (CBC + SHA-256 authentication)
 * Single-file utility: includes GOST2-128, SHA-256, CBC, IV generation, and I/O.
 *
 * Build:
 *   Unix/macOS: gcc gost2-128-cbc.c -o gost2file -Wall
 *   Windows (MinGW): gcc gost2-128-cbc.c -o gost2file -lbcrypt -Wall
 *
 * Usage:
 *   gost2file c <input_file>   -> produces <input_file>.gost2
 *   gost2file d <input_file>   -> removes .gost2 suffix if present, else appends .dec
 *
 * File format (encrypted):
 *   [16 bytes IV (clear)] [ciphertext (PKCS#7 padded)] [32 bytes SHA-256 over ciphertext only]
 *
 * Password:
 *   Asked interactively (not via CLI). Not echoed on screen.
 *
 * Randomness:
 *   - Preferred: arc4random_buf (BSD/macOS)
 *   - Else: /dev/urandom (Unix)
 *   - Else: BCryptGenRandom (Windows)
 *   - Else (LAST RESORT): srand(time(NULL)) + rand()
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#if defined(_WIN32)
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#  include <conio.h>
#  include <bcrypt.h> /* link with -lbcrypt */
#  pragma comment(lib, "bcrypt.lib")
#else
#  include <unistd.h>
#  include <termios.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <fcntl.h>
#endif

/* =========================
 *      GOST2-128 CORE
 * ========================= */

typedef uint64_t word64;

#define n1 512 /* 4096-bit GOST2-128 key for 64 * 64-bit subkeys */

static int x1,x2,i_g;
static unsigned char h2[n1];
static unsigned char h1[n1*3];

static void init_gost_keyhash(void)
{
   x1 = 0;
   x2 = 0;
   for (i_g = 0; i_g < n1; i_g++) h2[i_g] = 0;
   for (i_g = 0; i_g < n1; i_g++) h1[i_g] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13,199,11,67,237,193,164,77,115,184,141,222,73,38,147,36,150,87,21,104,12,61,156,101,111,145,
       119,22,207,35,198,37,171,167,80,30,219,28,213,121,86,29,214,242,6,4,89,162,110,175,19,157,3,88,234,94,144,118,159,239,100,17,182,173,238,
        68,16,79,132,54,163,52,9,58,57,55,229,192,170,226,56,231,187,158,70,224,233,245,26,47,32,44,247,8,251,20,197,185,109,153,204,218,93,178,
       212,137,84,174,24,120,130,149,72,180,181,208,255,189,152,18,143,176,60,249,27,227,128,139,243,253,59,123,172,108,211,96,138,10,215,42,225,40,81,
        65,90,25,98,126,154,64,124,116,122,5,1,168,83,190,131,191,244,240,235,177,155,228,125,66,43,201,248,220,129,188,230,62,75,71,78,34,31,216,
       254,136,91,114,106,46,217,196,92,151,209,133,51,236,33,252,127,179,69,7,183,105,146,97,39,15,205,112,200,166,223,45,48,246,186,41,148,140,107,
        76,85,95,194,142,50,49,134,23,135,169,221,210,203,63,165,82,161,202,53,14,206,232,103,102,195,117,250,99,0,74,160,241,2,113};
       
    int b1,b2,b3,b4,b5;
    b4=0;
    while (b6) {
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];
            x1 = h2[x2] ^= s4[b5 ^ x1];
        }
        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
        }
    }
}

static void end_gost_keyhash(unsigned char h4[n1])
{
    unsigned char h3[n1];
    int j, n4;
    n4 = n1 - x2;
    for (j = 0; j < n4; j++) h3[j] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (j = 0; j < n1; j++) h4[j] = h1[j];
}

/* create 64 * 64-bit subkeys from h4 hash */
static void create_keys(unsigned char h4[n1],word64 key[64])
{
  int k=0;
  for (int i=0;i<64;i++) {
      key[i]=0;
      for (int z=0;z<8;z++) key[i]=(key[i]<<8)+(h4[k++]&0xff);
  }
}

static unsigned char const k1[16] = {0x4,0xA,0x9,0x2,0xD,0x8,0x0,0xE,0x6,0xB,0x1,0xC,0x7,0xF,0x5,0x3};
static unsigned char const k2[16] = {0xE,0xB,0x4,0xC,0x6,0xD,0xF,0xA,0x2,0x3,0x8,0x1,0x0,0x7,0x5,0x9};
static unsigned char const k3[16] = {0x5,0x8,0x1,0xD,0xA,0x3,0x4,0x2,0xE,0xF,0xC,0x7,0x6,0x0,0x9,0xB};
static unsigned char const k4[16] = {0x7,0xD,0xA,0x1,0x0,0x8,0x9,0xF,0xE,0x4,0x6,0xC,0xB,0x2,0x5,0x3};
static unsigned char const k5[16] = {0x6,0xC,0x7,0x1,0x5,0xF,0xD,0x8,0x4,0xA,0x9,0xE,0x0,0x3,0xB,0x2};
static unsigned char const k6[16] = {0x4,0xB,0xA,0x0,0x7,0x2,0x1,0xD,0x3,0x6,0x8,0x5,0x9,0xC,0xF,0xE};
static unsigned char const k7[16] = {0xD,0xB,0x4,0x1,0x3,0xF,0x5,0x9,0x0,0xA,0xE,0x7,0x6,0x8,0x2,0xC};
static unsigned char const k8[16] = {0x1,0xF,0xD,0x0,0x5,0x7,0xA,0x4,0x9,0x2,0x3,0xE,0x6,0xB,0x8,0xC};

static unsigned char const k9[16]  = {0xC,0x4,0x6,0x2,0xA,0x5,0xB,0x9,0xE,0x8,0xD,0x7,0x0,0x3,0xF,0x1};
static unsigned char const k10[16] = {0x6,0x8,0x2,0x3,0x9,0xA,0x5,0xC,0x1,0xE,0x4,0x7,0xB,0xD,0x0,0xF};
static unsigned char const k11[16] = {0xB,0x3,0x5,0x8,0x2,0xF,0xA,0xD,0xE,0x1,0x7,0x4,0xC,0x9,0x6,0x0};
static unsigned char const k12[16] = {0xC,0x8,0x2,0x1,0xD,0x4,0xF,0x6,0x7,0x0,0xA,0x5,0x3,0xE,0x9,0xB};
static unsigned char const k13[16] = {0x7,0xF,0x5,0xA,0x8,0x1,0x6,0xD,0x0,0x9,0x3,0xE,0xB,0x4,0x2,0xC};
static unsigned char const k14[16] = {0x5,0xD,0xF,0x6,0x9,0x2,0xC,0xA,0xB,0x7,0x8,0x1,0x4,0x3,0xE,0x0};
static unsigned char const k15[16] = {0x8,0xE,0x2,0x5,0x6,0x9,0x1,0xC,0xF,0x4,0xB,0x0,0xD,0xA,0x3,0x7};
static unsigned char const k16[16] = {0x1,0x7,0xE,0xD,0x0,0x5,0x8,0x3,0x4,0xF,0xA,0x6,0x9,0xC,0xB,0x2};

static unsigned char k175[256], k153[256], k131[256], k109[256], k87[256], k65[256], k43[256], k21[256];

static void kboxinit(void)
{
	for (int i=0; i<256; i++) {
		k175[i] = k16[i >> 4] << 4 | k15[i & 15];
		k153[i] = k14[i >> 4] << 4 | k13[i & 15];
		k131[i] = k12[i >> 4] << 4 | k11[i & 15];
		k109[i] = k10[i >> 4] << 4 | k9[i & 15];
		k87[i]  = k8[i >> 4]  << 4 | k7[i & 15];
		k65[i]  = k6[i >> 4]  << 4 | k5[i & 15];
		k43[i]  = k4[i >> 4]  << 4 | k3[i & 15];
		k21[i]  = k2[i >> 4]  << 4 | k1[i & 15];
	}
}

#if __GNUC__
__inline__
#endif
static word64 f(word64 x)
{
	word64 y = x >> 32;
	word64 z = x & 0xffffffff;

	y = ((word64)k87[y>>24 & 255]  << 24) | ((word64)k65[y>>16 & 255] << 16) |
	    ((word64)k43[y>> 8 & 255]  <<  8) | ((word64)k21[y & 255]);

	z = ((word64)k175[z>>24 & 255] << 24) | ((word64)k153[z>>16 & 255] << 16) |
	    ((word64)k131[z>> 8 & 255] <<  8) | ((word64)k109[z & 255]);

	x = (y << 32) | (z & 0xffffffff);
	return (x<<11) | (x>>(64-11));
}

static void gostcrypt(word64 const in[2], word64 out[2], word64 key[64])
{
	register word64 a = in[0], b = in[1];
	int k=0;
	for (int i=0;i<32;i++){
	    b ^= f(a + key[k++]);
	    a ^= f(b + key[k++]);
	}
	out[0] = b; out[1] = a;
}

static void gostdecrypt(word64 const in[2], word64 out[2], word64 key[64])
{
	register word64 a = in[0], b = in[1];
	int k=63;
	for (int i=0;i<32;i++){
	    b ^= f(a + key[k--]);
	    a ^= f(b + key[k--]);
	}
	out[0] = b; out[1] = a;
}

/* =========================
 *          SHA-256
 * ========================= */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    unsigned char data[64];
    size_t datalen;
} sha256_ctx;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x)  (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k256[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(sha256_ctx *ctx, const unsigned char data[])
{
    uint32_t m[64], a,b,c,d,e,f,g,h,t1,t2;
    for (uint32_t i=0,j=0;i<16;i++,j+=4)
        m[i] = (data[j]<<24) | (data[j+1]<<16) | (data[j+2]<<8) | (data[j+3]);
    for (uint32_t i=16;i<64;i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];

    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];

    for (uint32_t i=0;i<64;i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d + t1; d=c; c=b; b=a; a=t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx)
{
    ctx->datalen=0; ctx->bitlen=0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85; ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c; ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len)
{
    for (size_t i=0;i<len;i++){
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen==64){
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, unsigned char hash[32])
{
    size_t i = ctx->datalen;
    ctx->bitlen += (uint64_t)ctx->datalen * 8;

    /* Pad */
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;

    /* Append length (big-endian) */
    for (int j=7;j>=0;j--) ctx->data[i++] = (unsigned char)((ctx->bitlen >> (j*8)) & 0xFF);

    sha256_transform(ctx, ctx->data);

    for (i=0;i<8;i++){
        hash[i*4+0] = (unsigned char)((ctx->state[i] >> 24) & 0xFF);
        hash[i*4+1] = (unsigned char)((ctx->state[i] >> 16) & 0xFF);
        hash[i*4+2] = (unsigned char)((ctx->state[i] >> 8) & 0xFF);
        hash[i*4+3] = (unsigned char)(ctx->state[i] & 0xFF);
    }
}

/* =========================
 *       Utilities
 * ========================= */

#define BLOCK_SIZE 16
#define READ_CHUNK  (64*1024)

static void be_bytes_to_words(const unsigned char in[16], word64 out[2])
{
    word64 a=0,b=0;
    for (int i=0;i<8;i++){ a = (a<<8) | in[i]; }
    for (int i=8;i<16;i++){ b = (b<<8) | in[i]; }
    out[0]=a; out[1]=b;
}

static void be_words_to_bytes(const word64 in[2], unsigned char out[16])
{
    for (int i=7;i>=0;i--) { out[7-i]  = (unsigned char)((in[0] >> (i*8)) & 0xFF); }
    for (int i=7;i>=0;i--) { out[15-i] = (unsigned char)((in[1] >> (i*8)) & 0xFF); }
}

/* Password prompt with no echo (cross-platform) */
static void prompt_password(char *buf, size_t buflen, const char *prompt)
{
#if defined(_WIN32)
    fputs(prompt, stdout); fflush(stdout);
    size_t idx=0; int ch;
    while ((ch = _getch()) != '\r' && ch != '\n' && ch != EOF) {
        if (ch == 3) exit(1); /* Ctrl+C */
        if (ch == '\b') { if (idx>0) idx--; continue; }
        if (idx+1 < buflen) buf[idx++] = (char)ch;
    }
    buf[idx]='\0';
    fputs("\n", stdout);
#else
    struct termios oldt, newt;
    fputs(prompt, stdout); fflush(stdout);
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt; newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    if (!fgets(buf, (int)buflen, stdin)) { buf[0]='\0'; }
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fputs("\n", stdout);
    /* strip newline */
    size_t l=strlen(buf);
    if (l>0 && (buf[l-1]=='\n' || buf[l-1]=='\r')) buf[l-1]='\0';
#endif
}

/* IV generation with fallback chain */
static void generate_iv(unsigned char iv[BLOCK_SIZE])
{
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    /* Preferred: arc4random_buf */
    arc4random_buf(iv, BLOCK_SIZE);
    return;
#endif

#if !defined(_WIN32)
    /* Try /dev/urandom */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, iv, BLOCK_SIZE);
        close(fd);
        if (r == BLOCK_SIZE) return;
    }
#endif

#if defined(_WIN32)
    /* Try BCryptGenRandom */
    if (BCryptGenRandom(NULL, iv, BLOCK_SIZE, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0) return;
#endif

    /* LAST RESORT: srand(time(NULL)) + rand() */
    srand((unsigned)time(NULL));
    for (int i=0;i<BLOCK_SIZE;i++) {
        iv[i] = (unsigned char)(rand() & 0xFF);
    }
}

/* Derive 4096-bit key material from password using MD2II-based hashing,
   then expand to 64 subkeys. Password is treated as bytes */
static void derive_gost_subkeys_from_password(const char *password, word64 subkeys[64])
{
    unsigned char h4[n1];
    init_gost_keyhash();
    hashing((unsigned char*)password, strlen(password));
    end_gost_keyhash(h4);
    create_keys(h4, subkeys);
}

/* PKCS#7 padding */
static size_t pkcs7_pad(unsigned char *buf, size_t used, size_t cap)
{
    size_t pad = BLOCK_SIZE - (used % BLOCK_SIZE);
    if (used + pad > cap) return 0; /* not enough space */
    for (size_t i=0;i<pad;i++) buf[used+i] = (unsigned char)pad;
    return used + pad;
}

static int pkcs7_unpad(unsigned char *buf, size_t *len)
{
    if (*len == 0 || (*len % BLOCK_SIZE)!=0) return 0;
    unsigned char pad = buf[*len - 1];
    if (pad == 0 || pad > BLOCK_SIZE) return 0;
    for (size_t i=0;i<pad;i++) {
        if (buf[*len - 1 - i] != pad) return 0;
    }
    *len -= pad;
    return 1;
}

/* Output filename helpers */
static int has_suffix(const char *name, const char *suffix)
{
    size_t n = strlen(name), s = strlen(suffix);
    if (n < s) return 0;
    return strcmp(name + (n - s), suffix) == 0;
}

static void make_output_name_encrypt(const char *in, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s.gost2", in);
}

static void make_output_name_decrypt(const char *in, char *out, size_t outsz)
{
    if (has_suffix(in, ".gost2")) {
        size_t n = strlen(in) - 6;
        memcpy(out, in, n); out[n]='\0';
    } else {
        snprintf(out, outsz, "%s.dec", in);
    }
}

/* =========================
 *   CBC Encrypt / Decrypt
 * ========================= */

static void cbc_encrypt_stream(FILE *fin, FILE *fout, word64 subkeys[64], unsigned char iv[BLOCK_SIZE], int *err, unsigned char out_hash[32])
{
    /* Write IV first (clear) */
    if (fwrite(iv, 1, BLOCK_SIZE, fout) != BLOCK_SIZE) { *err=1; return; }

    unsigned char inbuf[READ_CHUNK + BLOCK_SIZE]; /* extra for padding */
    unsigned char outbuf[READ_CHUNK + BLOCK_SIZE];
    unsigned char prev[BLOCK_SIZE];
    memcpy(prev, iv, BLOCK_SIZE);

    sha256_ctx hctx; sha256_init(&hctx);

    size_t r;
    while ((r = fread(inbuf, 1, READ_CHUNK, fin)) == READ_CHUNK) {
        /* r is a multiple of anything; we need to process per 16-byte blocks.
           If r is not multiple of 16, keep tail for next read—but since READ_CHUNK is large,
           we will buffer remainder with next fread or final padding. For simplicity, process
           all full blocks and move any remainder to front. */
        size_t full = (r / BLOCK_SIZE) * BLOCK_SIZE;
        size_t rem  = r - full;

        /* process full blocks */
        for (size_t off=0; off<full; off += BLOCK_SIZE) {
            for (int i=0;i<BLOCK_SIZE;i++) inbuf[off+i] ^= prev[i];
            word64 inw[2], outw[2];
            be_bytes_to_words(&inbuf[off], inw);
            gostcrypt(inw, outw, subkeys);
            be_words_to_bytes(outw, &outbuf[off]);
            memcpy(prev, &outbuf[off], BLOCK_SIZE);
        }
        if (fwrite(outbuf, 1, full, fout) != full) { *err=1; return; }
        sha256_update(&hctx, outbuf, full);

        /* move remainder to the front for next iteration */
        if (rem) memmove(inbuf, inbuf + full, rem);

        /* read next chunk continues, prepend rem bytes */
        /* Next fread will overwrite from inbuf+rem; we manage rem via another fread into temp.
           Simpler: push rem back by using ungetc isn't practical; instead, handle by reading next and concatenating:
           We'll do an extra fread here to fill up to READ_CHUNK then loop again.
           But to keep code straightforward, we instead break here and handle remainder + final in one go. */
        if (rem) {
            /* read the rest into buffer to fill, then continue */
            size_t got = fread(inbuf + rem, 1, READ_CHUNK - rem, fin);
            r = rem + got;
            /* process all but keep tail for padding at end if needed */
            size_t full2 = (r / BLOCK_SIZE) * BLOCK_SIZE;
            size_t rem2  = r - full2;

            for (size_t off=0; off<full2; off += BLOCK_SIZE) {
                for (int i=0;i<BLOCK_SIZE;i++) inbuf[off+i] ^= prev[i];
                word64 inw[2], outw[2];
                be_bytes_to_words(&inbuf[off], inw);
                gostcrypt(inw, outw, subkeys);
                be_words_to_bytes(outw, &outbuf[off]);
                memcpy(prev, &outbuf[off], BLOCK_SIZE);
            }
            if (fwrite(outbuf, 1, full2, fout) != full2) { *err=1; return; }
            sha256_update(&hctx, outbuf, full2);

            /* move remainder to front and fall through to final padding */
            if (rem2) memmove(inbuf, inbuf + full2, rem2);
            r = rem2;
            break; /* exit while to do final padding */
        }
    }

    /* Final read (either EOF reached or we broke out with r = remainder) */
    size_t tail = r; /* may be < READ_CHUNK */
    /* Add PKCS#7 padding */
    size_t total = pkcs7_pad(inbuf, tail, sizeof(inbuf));
    if (total == 0) { *err=1; return; }

    /* Encrypt final padded blocks */
    for (size_t off=0; off<total; off += BLOCK_SIZE) {
        for (int i=0;i<BLOCK_SIZE;i++) inbuf[off+i] ^= prev[i];
        word64 inw[2], outw[2];
        be_bytes_to_words(&inbuf[off], inw);
        gostcrypt(inw, outw, subkeys);
        be_words_to_bytes(outw, &outbuf[off]);
        memcpy(prev, &outbuf[off], BLOCK_SIZE);
    }
    if (fwrite(outbuf, 1, total, fout) != total) { *err=1; return; }
    sha256_update(&hctx, outbuf, total);

    /* Write SHA-256 over ciphertext only (not including IV) */
    sha256_final(&hctx, out_hash);
    if (fwrite(out_hash, 1, 32, fout) != 32) { *err=1; return; }
}

static void cbc_decrypt_stream(FILE *fin, FILE *fout, word64 subkeys[64], int *err, int *auth_ok)
{
    *auth_ok = 0;

    /* Determine file size to separate trailing 32-byte hash */
    if (fseek(fin, 0, SEEK_END) != 0) { *err=1; return; }
    long fsz = ftell(fin);
    if (fsz < (long)(BLOCK_SIZE + 32)) { fprintf(stderr, "Error: input too small.\n"); *err=1; return; }

    long payload = fsz - 32; /* up to before hash */
    if (fseek(fin, 0, SEEK_SET) != 0) { *err=1; return; }

    /* Read IV */
    unsigned char iv[BLOCK_SIZE];
    if (fread(iv, 1, BLOCK_SIZE, fin) != BLOCK_SIZE) { *err=1; return; }

    /* Read stored hash (at end) */
    if (fseek(fin, payload, SEEK_SET) != 0) { *err=1; return; }
    unsigned char stored_hash[32];
    if (fread(stored_hash, 1, 32, fin) != 32) { *err=1; return; }

    /* Prepare to stream-decrypt ciphertext (between IV and payload end) */
    if (fseek(fin, BLOCK_SIZE, SEEK_SET) != 0) { *err=1; return; }
    long remaining = payload - BLOCK_SIZE;
    if (remaining <= 0 || (remaining % BLOCK_SIZE)!=0) { fprintf(stderr, "Error: invalid ciphertext size.\n"); *err=1; return; }

    unsigned char prev[BLOCK_SIZE]; memcpy(prev, iv, BLOCK_SIZE);
    unsigned char inbuf[READ_CHUNK];
    unsigned char outbuf[READ_CHUNK];
    sha256_ctx hctx; sha256_init(&hctx);

    while (remaining > 0) {
        size_t toread = (remaining > READ_CHUNK) ? READ_CHUNK : (size_t)remaining;
        if (toread % BLOCK_SIZE) toread -= (toread % BLOCK_SIZE); /* align */
        size_t r = fread(inbuf, 1, toread, fin);
        if (r != toread) { *err=1; return; }

        /* hash ciphertext */
        sha256_update(&hctx, inbuf, r);

        /* decrypt blocks */
        for (size_t off=0; off<r; off += BLOCK_SIZE) {
            unsigned char cpy[BLOCK_SIZE];
            memcpy(cpy, &inbuf[off], BLOCK_SIZE);
            word64 inw[2], outw[2];
            be_bytes_to_words(&inbuf[off], inw);
            gostdecrypt(inw, outw, subkeys);
            be_words_to_bytes(outw, &outbuf[off]);
            /* XOR with previous ciphertext (CBC) */
            for (int i=0;i<BLOCK_SIZE;i++) outbuf[off+i] ^= prev[i];
            memcpy(prev, cpy, BLOCK_SIZE);
        }

        /* We cannot write final block until padding is checked; so buffer all except we can keep last block aside.
           For simplicity and memory efficiency, we will write progressively and only buffer the very last block:
           Strategy: If this is not the final read (remaining > r), write all outbuf; else, keep last block to unpad. */
        remaining -= (long)r;
        if (remaining > 0) {
            if (fwrite(outbuf, 1, r, fout) != r) { *err=1; return; }
        } else {
            /* Last chunk: remove PKCS#7 padding on its last block */
            if (r < BLOCK_SIZE) { *err=1; return; } /* should not happen */
            size_t keep = r - BLOCK_SIZE;
            if (keep) { if (fwrite(outbuf, 1, keep, fout) != keep) { *err=1; return; } }

            unsigned char lastblk[BLOCK_SIZE];
            memcpy(lastblk, outbuf + keep, BLOCK_SIZE);
            size_t lastlen = BLOCK_SIZE;
            if (!pkcs7_unpad(lastblk, &lastlen)) {
                fprintf(stderr, "Error: invalid padding.\n");
                *err=1; return;
            }
            if (lastlen) { if (fwrite(lastblk, 1, lastlen, fout) != lastlen) { *err=1; return; } }
        }
    }

    /* Verify hash */
    unsigned char calc_hash[32];
    sha256_final(&hctx, calc_hash);
    if (memcmp(calc_hash, stored_hash, 32) == 0) *auth_ok = 1;
}

/* =========================
 *            MAIN
 * ========================= */

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s c|d <input_file>\n", prog);
}

int main(int argc, char **argv)
{
    if (argc != 3) { usage(argv[0]); return 1; }
    int mode_encrypt = 0, mode_decrypt = 0;
    if (strcmp(argv[1], "c")==0) mode_encrypt = 1;
    else if (strcmp(argv[1], "d")==0) mode_decrypt = 1;
    else { usage(argv[0]); return 1; }

    const char *inpath = argv[2];
    char outpath[4096];
    if (mode_encrypt) make_output_name_encrypt(inpath, outpath, sizeof(outpath));
    else make_output_name_decrypt(inpath, outpath, sizeof(outpath));

    /* Open files */
    FILE *fin = fopen(inpath, "rb");
    if (!fin) { fprintf(stderr, "Error: cannot open input '%s': %s\n", inpath, strerror(errno)); return 1; }
    FILE *fout = fopen(outpath, "wb");
    if (!fout) { fprintf(stderr, "Error: cannot create output '%s': %s\n", outpath, strerror(errno)); fclose(fin); return 1; }

    /* Read password (not from CLI) */
    char password[256];
    prompt_password(password, sizeof(password), "Enter password: ");

    /* Init cipher tables and derive subkeys */
    kboxinit();
    word64 subkeys[64];
    derive_gost_subkeys_from_password(password, subkeys);
    /* Zero password buffer in memory (basic hygiene) */
    memset(password, 0, sizeof(password));

    int err=0;
    if (mode_encrypt) {
        unsigned char iv[BLOCK_SIZE];
        unsigned char hash_out[32];
        generate_iv(iv);
        cbc_encrypt_stream(fin, fout, subkeys, iv, &err, hash_out);
        if (!err) {
            printf("Encryption completed. Output: %s\n", outpath);
        }
    } else {
        int auth_ok=0;
        cbc_decrypt_stream(fin, fout, subkeys, &err, &auth_ok);
        if (!err) {
            printf("Decryption completed. Output: %s\n", outpath);
            printf("Authentication %s\n", auth_ok ? "OK" : "FAILED");
        }
    }

    fclose(fin); fclose(fout);

    if (err) {
        fprintf(stderr, "Operation failed due to an error.\n");
        /* Best-effort: remove incomplete output */
        remove(outpath);
        return 2;
    }
    return 0;
}
