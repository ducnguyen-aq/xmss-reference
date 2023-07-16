#include "../xmss_core.h"
#include <stdint.h>
#include <stdio.h>

int main(void) {
	const char *params[] = {
		"XMSS-SHA2_10_256",
		"XMSS-SHA2_16_256",
		"XMSS-SHA2_20_256",
		"XMSS-SHAKE_10_256",
		"XMSS-SHAKE_16_256",
		"XMSS-SHAKE_20_256",
		"XMSS-SHA2_10_512",
		"XMSS-SHA2_16_512",
		"XMSS-SHA2_20_512",
		"XMSS-SHAKE_10_512",
		"XMSS-SHAKE_16_512",
		"XMSS-SHAKE_20_512",
	};
	uint32_t oid;
	xmss_params xmss;
	printf("| Algorithm | oid | sk | pk | sig | n\n");
	for (int i = 0; i < 12; i++) {
		if (xmss_str_to_oid(&oid, params[i])) {
			printf("xmss_str_to_oid failed\n");
			return -1;
		}

		if (xmss_parse_oid(&xmss, oid)) {
			printf("xmss_parse_oid\n");
			return -1;
		}

		printf("| %s \t\t| 0x%02x | %5llu | %3u | %5u | %2u\n", params[i], oid, xmss.sk_bytes,
		       xmss.pk_bytes, xmss.sig_bytes, xmss.n);
	}

	const char *params_mt[] = {
		"XMSSMT-SHA2_20/2_256",
		"XMSSMT-SHA2_20/4_256",
		"XMSSMT-SHA2_40/2_256",
		"XMSSMT-SHA2_40/4_256",
		"XMSSMT-SHA2_40/8_256",
		"XMSSMT-SHA2_60/3_256",
		"XMSSMT-SHA2_60/6_256",
		"XMSSMT-SHA2_60/12_256",
		"XMSSMT-SHAKE_20/2_256",
		"XMSSMT-SHAKE_20/4_256",
		"XMSSMT-SHAKE_40/2_256",
		"XMSSMT-SHAKE_40/4_256",
		"XMSSMT-SHAKE_40/8_256",
		"XMSSMT-SHAKE_60/3_256",
		"XMSSMT-SHAKE_60/6_256",
		"XMSSMT-SHAKE_60/12_256",
	};
	uint32_t oid_mt;

	for (int i = 0; i < 16; i++) {
		if (xmssmt_str_to_oid(&oid_mt, params_mt[i])) {
			printf("xmssmt_str_to_oid failed\n");
			return -1;
		}

		if (xmssmt_parse_oid(&xmss, oid_mt)) {
			printf("xmssmt_parse_oid\n");
			return -1;
		}

		printf("| %s  \t| 0x%02x | %5llu | %3u | %5u | %2u\n", params_mt[i], oid_mt, xmss.sk_bytes,
		       xmss.pk_bytes, xmss.sig_bytes, xmss.n);
	}
	return 0;
}
