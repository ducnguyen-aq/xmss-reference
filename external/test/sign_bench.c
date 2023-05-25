#include "../sign.h"
#include "../sign_params.h"
#include "../randombytes.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define XMSS_SIGNATURES 8

#define CALC(start, stop) ((stop.tv_sec - start.tv_sec) * 1e6 + (stop.tv_nsec - start.tv_nsec) / 1e3)

/*
 * This array collect the performance number
 * and then use it to compute average and median number
 */
unsigned long long t_sign[XMSS_SIGNATURES];
unsigned long long t_verify[XMSS_SIGNATURES];

static int cmp_llu(const void *a, const void *b) {
	if (*(unsigned long long *)a < * (unsigned long long *)b) {
		return -1;
	}
	if (*(unsigned long long *)a > *(unsigned long long *)b) {
		return 1;
	}
	return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen) {
	qsort(l, llen, sizeof(unsigned long long), cmp_llu);

	if (llen % 2) {
		return l[llen / 2];
	} else {
		return (l[llen / 2 - 1] + l[llen / 2]) / 2;
	}
}

static unsigned long long average(unsigned long long *t, size_t tlen) {
	unsigned long long acc = 0;
	for (size_t i = 0; i < tlen; i++) {
		acc += t[i];
	}
	return acc / tlen;
}

static void print_results(unsigned long long *t, size_t tlen) {
	printf("\tmedian        : %llu us\n", median(t, tlen));
	printf("\taverage       : %llu us\n", average(t, tlen));
	printf("\n");
}

/*
 * Benchmark Keygen
 */
int bench_keygen(unsigned char *pk, unsigned char *sk) {
	struct timespec start, stop;
	int ret;
	double result;

	printf("%s Benchmark:\n", XMSS_OID);

	clock_gettime(CLOCK_REALTIME, &start);
	ret = crypto_sign_keypair(pk, sk);
	clock_gettime(CLOCK_REALTIME, &stop);

	result = CALC(start, stop);

	printf("Keygen: %lf us\n", result);

	return ret;
}

/*
 * Benchmark Sign and Verify
 */
int bench_sign_verify(unsigned char *sm,
                      const unsigned char *m,
                      const unsigned long long mlen,
                      unsigned char *sk,
                      const unsigned char *pk) {
	struct timespec start, stop;
	int ret;

	unsigned long long smlen = 0;

	for (int i = 0; i < XMSS_SIGNATURES; i++) {
		clock_gettime(CLOCK_REALTIME, &start);
		ret = crypto_sign(sm, &smlen, m, mlen, sk);
		clock_gettime(CLOCK_REALTIME, &stop);

		t_sign[i] = CALC(start, stop);

		if (ret) {
			return 1;
		}

		if (smlen != CRYPTO_BYTES) {
			return 1;
		}

		clock_gettime(CLOCK_REALTIME, &start);
		ret = crypto_sign_open(m, mlen, sm, smlen, pk);
		clock_gettime(CLOCK_REALTIME, &stop);

		t_verify[i] = CALC(start, stop);

		if (ret) {
			return 1;
		}
	}
	printf("Sign: ");
	print_results(t_sign, XMSS_SIGNATURES);
	printf("Verify: ");
	print_results(t_verify, XMSS_SIGNATURES);

	return 0;
}

/*
 * Test maximum and remaining signatures
 */
int test_remain(unsigned char *sk) {
	unsigned long long remain, max;

	if (crypto_remaining_signatures(&remain, sk)) {
		return 1;
	}

	if (crypto_total_signatures(&max, sk)) {
		return 1;
	}

	if (max - remain != XMSS_SIGNATURES) {
		// Incorrect count
		return 1;
	}

	return 0;
}

int main(void) {

	unsigned char pk[CRYPTO_PUBLIC_KEY];
	unsigned char sk[CRYPTO_SECRET_KEY];
	unsigned char sm[CRYPTO_BYTES];
	unsigned char m[64];
	const unsigned long long mlen = sizeof(m);

	randombytes(m, sizeof(m));

	if (bench_keygen(pk, sk)) {
		return 1;
	}

	if (bench_sign_verify(sm, m, mlen, sk, pk)) {
		return 1;
	}

	if (test_remain(sk)) {
		return 1;
	}

	return 0;
}
