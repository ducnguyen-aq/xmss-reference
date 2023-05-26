#include <oqs/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../sign.h"
#include "../sign_params.h"

#define XMSS_SIGNATURES 8

static void print_hex(const unsigned char *a, int length, const char *string) {
	printf("%s[%d] = \n", string, length);
	for (int i = 0; i < length; i++) {
		printf("%02x", a[i]);
	}
	printf("\n");
}

/*
 * Test Keygen
 */
int test_keygen(unsigned char *pk, unsigned char *sk) {
	return crypto_sign_keypair(pk, sk);
}

/*
 * Test Sign and Verify
 */
int test_sign_verify(unsigned char *sm,
                     const unsigned char *m,
                     const unsigned long long mlen,
                     unsigned char *sk,
                     const unsigned char *pk) {
	unsigned long long smlen = 0;

	for (int i = 0; i < XMSS_SIGNATURES; i++) {
		if (crypto_sign(sm, &smlen, m, mlen, sk)) {
			printf("    Unable to generate signature\n");
			break;
		}

		if (smlen != CRYPTO_BYTES) {
			printf("Incorrect Signature size: %llu != %d", smlen, CRYPTO_BYTES);
			break;
		}

		print_hex(sm, smlen, "sm");

		if (crypto_sign_open(m, mlen, sm, smlen, pk)) {
			printf("    Unable to verify signature\n");
			break;
		}
	}

	return 0;
}

/*
 * Test maximum and remaining signatures
 */
int test_remain(unsigned char *sk) {
	unsigned long long remain, max;

	if (crypto_remaining_signatures(&remain, sk)) {
		printf("    Can't get remaining signatures from sk\n");
		return 1;
	}

	if (crypto_total_signatures(&max, sk)) {
		printf("    Can't get maximum signatures from sk\n");
		return 1;
	}

	printf("remain = %lld\n", remain);
	printf("max = %lld\n", max);

	if (max - remain != XMSS_SIGNATURES) {
		printf("    Incorrect used signatures\n");
		return 1;
	}

	return 0;
}

int main(void) {
	unsigned char pk[CRYPTO_PUBLICKEYBYTES];
	unsigned char sk[CRYPTO_SECRETKEYBYTES];
	unsigned char sm[CRYPTO_BYTES];
	unsigned char m[64];
	unsigned char buf[48];
	const unsigned long long mlen = sizeof(m);

	// Initialize the test message to 'A'*64
	memset(m, 0x41, sizeof(m));

	// Init the seed for NIST-KAT AES random generator
	memset(buf, 0, sizeof(buf));
	/* Using AES as random generator */
    if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        printf("Initialize seed failed\n");
        return 1;
    }

    /* Initialize NIST KAT seed by value in `buf` */
    OQS_randombytes_nist_kat_init_256bit(buf, NULL);
    
	// Start generating KAT
	printf("%s KAT:\n", XMSS_OID);

	if (test_keygen(pk, sk)) {
		printf("    Unable to generate keypair\n");
		return 1;
	}

	print_hex(pk, CRYPTO_PUBLICKEYBYTES, "pk");
	print_hex(sk, CRYPTO_SECRETKEYBYTES, "sk");
	print_hex(m, mlen, "m");

	if (test_sign_verify(sm, m, mlen, sk, pk)) {
		return 1;
	}

	print_hex(sk, CRYPTO_SECRETKEYBYTES, "sk_final");

	if (test_remain(sk)) {
		printf("    Unable to check remaining signature\n");
		return 1;
	}

	return 0;
}
