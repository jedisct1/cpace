#ifndef crypto_cpace_H
#define crypto_cpace_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define crypto_cpace_PUBLICDATABYTES (16 + 32)
#define crypto_cpace_RESPONSEBYTES 32
#define crypto_cpace_SHAREDKEYBYTES 32

typedef struct crypto_cpace_shared_keys_ {
    unsigned char client_sk[crypto_cpace_SHAREDKEYBYTES];
    unsigned char server_sk[crypto_cpace_SHAREDKEYBYTES];
} crypto_cpace_shared_keys;

typedef struct crypto_cpace_state_ {
    unsigned char session_id[16];
    unsigned char p[32];
    unsigned char r[32];
} crypto_cpace_state;

int crypto_cpace_init(void);

int crypto_cpace_step1(crypto_cpace_state *ctx,
                       unsigned char public_data[crypto_cpace_PUBLICDATABYTES],
                       const char *password, size_t password_len,
                       const char *id_a, unsigned char id_a_len,
                       const char *id_b, unsigned char id_b_len,
                       const unsigned char *ad, size_t ad_len);

int crypto_cpace_step2(
    unsigned char             response[crypto_cpace_RESPONSEBYTES],
    const unsigned char       public_data[crypto_cpace_PUBLICDATABYTES],
    crypto_cpace_shared_keys *shared_keys, const char *password,
    size_t password_len, const char *id_a, unsigned char id_a_len,
    const char *id_b, unsigned char id_b_len, const unsigned char *ad,
    size_t ad_len);

int
crypto_cpace_step3(crypto_cpace_state *      ctx,
                   crypto_cpace_shared_keys *shared_keys,
                   const unsigned char response[crypto_cpace_RESPONSEBYTES]);

#ifdef __cplusplus
}
#endif

#endif
