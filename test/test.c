#include <sodium.h>

#include "crypto_cpace.h"

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
