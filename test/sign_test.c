#include "../sign.h"
#include "../sign_params.h"
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

#if DEBUG
static void print_hex(const unsigned char *a, int length, const char *string)
{
    printf("%s[%d] = \n", string, length);
    for (int i = 0; i < length; i++)
    {
        printf("%02x", a[i]);
    }
    printf("\n");
}
#endif

#if BENCH
static int cmp_llu(const void *a, const void *b)
{
    if (*(unsigned long long *)a < *(unsigned long long *)b)
        return -1;
    if (*(unsigned long long *)a > *(unsigned long long *)b)
        return 1;
    return 0;
}

static unsigned long long median(unsigned long long *l, size_t llen)
{
    qsort(l, llen, sizeof(unsigned long long), cmp_llu);

    if (llen % 2)
        return l[llen / 2];
    else
        return (l[llen / 2 - 1] + l[llen / 2]) / 2;
}

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc = 0;
    for (size_t i = 0; i < tlen; i++)
    {
        acc += t[i];
    }
    return acc / tlen;
}


static void print_results(unsigned long long *t, size_t tlen)
{
    printf("\tmedian        : %llu us\n", median(t, tlen));
    printf("\taverage       : %llu us\n", average(t, tlen));
    printf("\n");
}
#endif

/*
 * Test keygen
 */
int test_keygen(unsigned char *pk, unsigned char *sk)
{
    struct timespec start, stop;
    int ret;
    double result;

    printf("Generating keypair.. %s\n", XMSS_OID);

    clock_gettime(CLOCK_REALTIME, &start);
    ret = crypto_sign_keypair(pk, sk);
    clock_gettime(CLOCK_REALTIME, &stop);

    result = CALC(start, stop);

#if BENCH
    printf("took %lf us (%.2lf sec)\n", result, result / 1e6);
#endif
    (void)result;

    return ret;
}

/*
 * Test Sign and Verify
 */
int test_sign_verify(unsigned char *sm,
                     const unsigned char *m,
                     const unsigned long long mlen,
                     unsigned char *sk,
                     const unsigned char *pk)
{
    struct timespec start, stop;
    int ret;

    printf("Sign and Verify %d signatures..\n", XMSS_SIGNATURES);

    unsigned long long smlen = 0;

    for (int i = 0; i < XMSS_SIGNATURES; i++)
    {
        clock_gettime(CLOCK_REALTIME, &start);
        ret = crypto_sign(sm, &smlen, m, mlen, sk);
        clock_gettime(CLOCK_REALTIME, &stop);

        t_sign[i] = CALC(start, stop);

        if (ret)
        {
            printf("    Unable to generate signature\n");
            break;
        }

        if (smlen != CRYPTO_BYTES)
        {
            printf("Incorrect Signature size: %llu != %d", smlen, CRYPTO_BYTES);
            break;
        }

#if DEBUG
        print_hex(sm, smlen, "signature");
#endif

        clock_gettime(CLOCK_REALTIME, &start);
        ret = crypto_sign_open(m, mlen, sm, smlen, pk);
        clock_gettime(CLOCK_REALTIME, &stop);

        t_verify[i] = CALC(start, stop);

        if (ret)
        {
            printf("    Unable to verify signature\n");
            break;
        }
    }
#if BENCH
    print_results(t_sign, XMSS_SIGNATURES);
    print_results(t_verify, XMSS_SIGNATURES);
#endif
    return ret;
}

/*
 * Testing remaining signatures
 */
int test_remain(unsigned char *sk)
{
    unsigned long long remain = 0, max;
    uint32_t oid = 0;
    xmss_params params;
    int ret;
    ret = crypto_remaining_signatures(&remain, sk);

    for (int i = 0; i < XMSS_OID_LEN; i++)
    {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

#if XMSSMT
    if (xmssmt_parse_oid(&params, oid))
#else
    if (xmss_parse_oid(&params, oid))
#endif
    {
        return -1;
    }
    max = ((1ULL << params.full_height) - 1);

    printf("used = %lld, remain = %lld, max = %lld\n", max - remain, remain, max);

    // Incorrect count;
    if (max - remain != XMSS_SIGNATURES)
    {
        printf("    Incorrect used signatures\n");
        return 1;
    }

    return ret;
}

int main(void)
{
    // Keygen test
    int ret;
    unsigned char pk[CRYPTO_PUBLIC_KEY];
    unsigned char sk[CRYPTO_SECRET_KEY];
    unsigned char sm[CRYPTO_BYTES];

    unsigned char m[] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    unsigned long long mlen = sizeof(m);

    ret = test_keygen(pk, sk);

    if (ret)
    {
        printf("    Unable to generate keypair\n");
        return 1;
    }

#if DEBUG
    print_hex(pk, CRYPTO_PUBLIC_KEY, "pk");
    print_hex(sk, CRYPTO_SECRET_KEY, "sk");
    print_hex(m, mlen, "message");
#endif

    ret |= test_sign_verify(sm, m, mlen, sk, pk);

    ret |= test_remain(sk);

    if (ret)
    {
        printf("    Unable to check remaining signature\n");
        return 1;
    }

#if DEBUG
    print_hex(sk, CRYPTO_SECRET_KEY, "sk_final");
#endif

    return 0;
}
