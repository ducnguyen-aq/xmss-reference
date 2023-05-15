#include <oqs/sha3.h>
#include "hash.h"

int core_hash(const xmss_params *params,
              unsigned char *out,
              const unsigned char *in, unsigned long long inlen)
{
    (void)params;
    OQS_SHA3_shake256(out, 32, in, inlen);
    return 0;
}
