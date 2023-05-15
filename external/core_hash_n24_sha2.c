#include <oqs/sha2.h>
#include <string.h>
#include "hash.h"

int core_hash(const xmss_params *params,
              unsigned char *out,
              const unsigned char *in, unsigned long long inlen)
{
    (void)params;
    unsigned char buf[32];
    OQS_SHA2_sha256(buf, in, inlen);
    memcpy(out, buf, 24);
    return 0;
}
