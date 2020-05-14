#include <sodium.h>
#include <string.h>

#include "crypto_cpace.h"

#define DSI1 "CPaceRistretto255-1"
#define DSI2 "CPaceRistretto255-2"
#define session_id_BYTES 16
#define hash_BLOCKSIZE 128

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

static int
ctx_init(crypto_cpace_state *const ctx, const char *password,
         size_t password_len, const char *id_a, unsigned char id_a_len,
         const char *id_b, unsigned char id_b_len, const unsigned char *ad,
         size_t ad_len)
{
    crypto_hash_sha512_state st;
    unsigned char            h[crypto_core_ristretto255_HASHBYTES];
    static unsigned char     zpad[hash_BLOCKSIZE];
    const size_t             dsi_len = sizeof DSI1 - 1U;
    size_t                   pad_len;

    COMPILER_ASSERT(sizeof ctx->session_id == session_id_BYTES &&
                    sizeof ctx->p == crypto_scalarmult_ristretto255_BYTES &&
                    sizeof ctx->r ==
                        crypto_scalarmult_ristretto255_SCALARBYTES);
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *) DSI1, dsi_len);
    crypto_hash_sha512_update(&st, (const unsigned char *) password,
                              password_len);
    pad_len = sizeof zpad - (dsi_len + password_len) & (sizeof zpad - 1);
    crypto_hash_sha512_update(&st, zpad, pad_len);
    crypto_hash_sha512_update(&st, ctx->session_id, session_id_BYTES);
    crypto_hash_sha512_update(&st, &id_a_len, 1);
    crypto_hash_sha512_update(&st, (const unsigned char *) id_a, id_a_len);
    crypto_hash_sha512_update(&st, &id_b_len, 1);
    crypto_hash_sha512_update(&st, (const unsigned char *) id_b, id_b_len);
    crypto_hash_sha512_update(&st, ad, ad_len);
    COMPILER_ASSERT(crypto_core_ristretto255_HASHBYTES ==
                    crypto_hash_sha512_BYTES);
    crypto_hash_sha512_final(&st, h);

    crypto_core_ristretto255_from_hash(ctx->p, h);
    crypto_core_ristretto255_scalar_random(ctx->r);

    return crypto_scalarmult_ristretto255(ctx->p, ctx->r, ctx->p);
}

static int
ctx_final(const crypto_cpace_state *ctx, crypto_cpace_shared_keys *shared_keys,
          const unsigned char op[crypto_scalarmult_ristretto255_BYTES],
          const unsigned char ya[crypto_scalarmult_ristretto255_BYTES],
          const unsigned char yb[crypto_scalarmult_ristretto255_BYTES])
{
    crypto_hash_sha512_state st;
    unsigned char            p[crypto_scalarmult_ristretto255_BYTES];
    unsigned char            h[crypto_hash_sha512_BYTES];

    /* crypto_scalarmult_*() rejects the identity element */
    if (crypto_scalarmult_ristretto255(p, ctx->r, op) != 0) {
        return -1;
    }
    crypto_hash_sha512_init(&st);
    crypto_hash_sha512_update(&st, (const unsigned char *) DSI2,
                              sizeof DSI2 - 1);
    crypto_hash_sha512_update(&st, ctx->session_id, session_id_BYTES);
    crypto_hash_sha512_update(&st, p, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_update(&st, ya, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_update(&st, yb, crypto_scalarmult_ristretto255_BYTES);
    crypto_hash_sha512_final(&st, h);
    COMPILER_ASSERT(sizeof h >= 2 * crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->client_sk, h, crypto_cpace_SHAREDKEYBYTES);
    memcpy(shared_keys->server_sk, h + crypto_cpace_SHAREDKEYBYTES,
           crypto_cpace_SHAREDKEYBYTES);

    return 0;
}

int
crypto_cpace_init(void)
{
    COMPILER_ASSERT(
        crypto_cpace_RESPONSEBYTES == crypto_scalarmult_ristretto255_BYTES &&
        crypto_cpace_PUBLICDATABYTES ==
            session_id_BYTES + crypto_scalarmult_ristretto255_BYTES);

    return sodium_init();
}

int
crypto_cpace_step1(crypto_cpace_state *ctx,
                   unsigned char public_data[crypto_cpace_PUBLICDATABYTES],
                   const char *password, size_t password_len, const char *id_a,
                   unsigned char id_a_len, const char *id_b,
                   unsigned char id_b_len, const unsigned char *ad,
                   size_t ad_len

)
{
    randombytes_buf(ctx->session_id, session_id_BYTES);
    if (ctx_init(ctx, password, password_len, id_a, id_a_len, id_b, id_b_len,
                 ad, ad_len) != 0) {
        return -1;
    }
    memcpy(public_data, ctx->session_id, session_id_BYTES);
    memcpy(public_data + session_id_BYTES, ctx->p,
           crypto_scalarmult_ristretto255_BYTES);

    return 0;
}

int
crypto_cpace_step2(
    unsigned char             response[crypto_cpace_RESPONSEBYTES],
    const unsigned char       public_data[crypto_cpace_PUBLICDATABYTES],
    crypto_cpace_shared_keys *shared_keys, const char *password,
    size_t password_len, const char *id_a, unsigned char id_a_len,
    const char *id_b, unsigned char id_b_len, const unsigned char *ad,
    size_t ad_len)
{
    crypto_cpace_state   ctx;
    const unsigned char *ya = public_data + session_id_BYTES;

    memcpy(ctx.session_id, public_data, session_id_BYTES);
    if (ctx_init(&ctx, password, password_len, id_a, id_a_len, id_b, id_b_len,
                 ad, ad_len) != 0) {
        return -1;
    }
    memcpy(response, ctx.p, crypto_scalarmult_ristretto255_BYTES);
    if (ctx_final(&ctx, shared_keys, ya, ya, response) != 0) {
        return -1;
    }
    sodium_memzero(&ctx, sizeof ctx);

    return 0;
}

int
crypto_cpace_step3(crypto_cpace_state *      ctx,
                   crypto_cpace_shared_keys *shared_keys,
                   const unsigned char response[crypto_cpace_RESPONSEBYTES])
{
    return ctx_final(ctx, shared_keys, response, ctx->p, response);
}
