# CPace-Ristretto255, a balanced PAKE

A CPace implementation for libsodium 1.0.17+

## Blurb

[CPace](https://tools.ietf.org/id/draft-haase-cpace-01.html) is a protocol for two parties that share a low-entropy secret (password) to derive a strong shared key without disclosing the secret to offline dictionary attacks.

CPace is a balanced PAKE, meaning that both parties must know the low-entropy secret.

Applications include pairing IoT and mobile applications using ephemeral pin codes, QR-codes, serial numbers, etc.

## Usage

The CPace protocol requires a single round trip.

It returns a set of two 256-bit (`crypto_cpace_SHAREDKEYBYTES` bytes) keys that can be used to communicate in both directions.

```c
#include "crypto_cpace.h"

#include <sodium.h>

/* A client identifier (username, email address, public key...) */
#define CLIENT_ID "client"

/* A server identifier (IP address, host name, public key...) */
#define SERVER_ID "server"

/* The shared password */
#define PASSWORD "password"

/* Optional additional data (application name, version, time stamp...) */
#define ADDITIONAL_DATA "additional data"

int
main(void)
{
    crypto_cpace_state       ctx;
    crypto_cpace_shared_keys shared_keys_computed_by_client;
    crypto_cpace_shared_keys shared_keys_computed_by_server;
    unsigned char            public_data[crypto_cpace_PUBLICDATABYTES];
    unsigned char            response[crypto_cpace_RESPONSEBYTES];
    char                     hex[crypto_cpace_SHAREDKEYBYTES * 2 + 1];

    /* [BOTH SIDES] Initialize the library - This just calls sodium_init() */
    if (crypto_cpace_init() != 0) {
        return 1;
    }

    /* [CLIENT SIDE] Compute public data to be sent to the server */
    if (crypto_cpace_step1(&ctx, public_data, PASSWORD, sizeof PASSWORD - 1,
                           CLIENT_ID, sizeof CLIENT_ID - 1, SERVER_ID,
                           sizeof SERVER_ID,
                           (const unsigned char *) ADDITIONAL_DATA,
                           sizeof ADDITIONAL_DATA) != 0) {
        return 1;
    }

    /* [SERVER SIDE] Compute the shared keys using the public data,
     * and return a response to send back to the client.
     */
    if (crypto_cpace_step2(
            response, public_data, &shared_keys_computed_by_server, PASSWORD,
            sizeof PASSWORD - 1, CLIENT_ID, sizeof CLIENT_ID - 1, SERVER_ID,
            sizeof SERVER_ID, (const unsigned char *) ADDITIONAL_DATA,
            sizeof ADDITIONAL_DATA) != 0) {
        return 1;
    }

    /* [CLIENT SIDE] Compute the shared keys using the server response */
    if (crypto_cpace_step3(&ctx, &shared_keys_computed_by_client, response) !=
        0) {
        return 1;
    }

    /* Verification */

    printf("Client key computed by the client: %s\n",
           sodium_bin2hex(hex, sizeof hex,
                          shared_keys_computed_by_client.client_sk,
                          crypto_cpace_SHAREDKEYBYTES));
    printf("Client key computed by the server: %s\n",
           sodium_bin2hex(hex, sizeof hex,
                          shared_keys_computed_by_server.client_sk,
                          crypto_cpace_SHAREDKEYBYTES));
    printf("Server key computed by the client: %s\n",
           sodium_bin2hex(hex, sizeof hex,
                          shared_keys_computed_by_client.server_sk,
                          crypto_cpace_SHAREDKEYBYTES));
    printf("Server key computed by the server: %s\n",
           sodium_bin2hex(hex, sizeof hex,
                          shared_keys_computed_by_server.server_sk,
                          crypto_cpace_SHAREDKEYBYTES));
    return 0;
}
```

## Notes

- This implementation uses the Ristretto255 group and SHA-512 as the hash function, so that it can trivially be ported to [wasm-crypto](https://github.com/jedisct1/wasm-crypto).
- Client and server identifiers have a maximum size of 255 bytes.
- A Rust version is available [here](https://github.com/jedisct1/rust-cpace).
