#ifndef NIST_PARAM_H
#define NIST_PARAM_H

#include "params.h"
#include "xmss.h"

#ifndef XMSSMT
#error "Please specify XMSS or XMSSMT."
#endif

#ifndef XMSS_OID_INT
#error "Please define XMSS_OID_INT XMSS {0x1, 0x4, 0x7, 0xa} or {0x2, 0x5, 0x8, 0xb} or {0x3, 0x6, 0x9, 0xc} or XMSSMT {0x1, 0x2} or {0x3, 0x4, 0x5} or {0x6, 0x7, 0x8}."
#endif

#if XMSSMT == 0
    /* 
    * Maximum signatures: 2^h - 1 = 2^10 - 1
    */
        #if XMSS_OID_INT == 0x1
            #define XMSS_OID "XMSS-SHA2_10_256"
            #define XMSS_SECRETKEYBYTES 1373
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2500
        #elif XMSS_OID_INT == 0x4
            #define XMSS_OID "XMSS-SHA2_10_512"
            #define XMSS_SECRETKEYBYTES 2653
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9092
        #elif XMSS_OID_INT == 0x7
            #define XMSS_OID "XMSS-SHAKE_10_256"
            #define XMSS_SECRETKEYBYTES 1373
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2500
        #elif XMSS_OID_INT == 0xa
            #define XMSS_OID "XMSS-SHAKE_10_512"
            #define XMSS_SECRETKEYBYTES 2653
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9092

    /* 
    * Maximum signatures: 2^h - 1 = 2^16 - 1
    */

        #elif XMSS_OID_INT == 0x2
            #define XMSS_OID "XMSS-SHA2_16_256"
            #define XMSS_SECRETKEYBYTES 2093
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2692
        #elif XMSS_OID_INT == 0x5
            #define XMSS_OID "XMSS-SHA2_16_512"
            #define XMSS_SECRETKEYBYTES 4045
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9476
        #elif XMSS_OID_INT == 0x8
            #define XMSS_OID "XMSS-SHAKE_16_256"
            #define XMSS_SECRETKEYBYTES 2093
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2692
        #elif XMSS_OID_INT == 0xb
            #define XMSS_OID "XMSS-SHAKE_16_512"
            #define XMSS_SECRETKEYBYTES 4045
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9476

    /* 
    * Maximum signatures: 2^h - 1 = 2^20 - 1
    */
        #elif XMSS_OID_INT == 0x3
            #define XMSS_OID "XMSS-SHA2_20_256"
            #define XMSS_SECRETKEYBYTES 2573
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2820
        #elif XMSS_OID_INT == 0x6
            #define XMSS_OID "XMSS-SHA2_20_512"
            #define XMSS_SECRETKEYBYTES 4973
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9732
        #elif XMSS_OID_INT == 0x9
            #define XMSS_OID "XMSS-SHAKE_20_256"
            #define XMSS_SECRETKEYBYTES 2573
            #define XMSS_PUBLICKEYBYTES 64
            #define XMSS_SIGNBYTES 2820
        #elif XMSS_OID_INT == 0xc
            #define XMSS_OID "XMSS-SHAKE_20_512"
            #define XMSS_SECRETKEYBYTES 4973
            #define XMSS_PUBLICKEYBYTES 128
            #define XMSS_SIGNBYTES 9732
        #else
            #error "Not supported XMSS_OID_INT"
        #endif

    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_REMAINING_SIG xmss_remaining_signatures
    #define XMSS_TOTAL_SIG xmss_total_signatures
#else 
    /* 
    * Maximum signatures: 2^h - 1 = 2^20 - 1
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #if XMSS_OID_INT == 0x1
        #define XMSS_OID "XMSSMT-SHA2_20/2_256"
        #define XMSS_SECRETKEYBYTES 5998
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 4963
    #elif XMSS_OID_INT == 0x2
        #define XMSS_OID "XMSSMT-SHA2_20/4_256"
        #define XMSS_SECRETKEYBYTES 10938
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 9251

    /* 
    * Maximum signatures: 2^h - 1 = 2^40 - 1
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */
    #elif XMSS_OID_INT == 0x3
        #define XMSS_OID "XMSSMT-SHA2_40/2_256"
        #define XMSS_SECRETKEYBYTES 9600
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 5605
    #elif XMSS_OID_INT == 0x4
        #define XMSS_OID "XMSSMT-SHA2_40/4_256"
        #define XMSS_SECRETKEYBYTES 15252
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 9893
    #elif XMSS_OID_INT == 0x5
        #define XMSS_OID "XMSSMT-SHA2_40/8_256"
        #define XMSS_SECRETKEYBYTES 24516
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 18469

    /* 
    * Maximum signatures: 2^h - 1 = 2^60 - 1
    * XMSS^MT has bigger signature and secret key (secret is not transfer), but better speed
    */

    #elif XMSS_OID_INT == 0x6
        #define XMSS_OID "XMSSMT-SHA2_60/3_256"
        #define XMSS_SECRETKEYBYTES 16629
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 8392
    #elif XMSS_OID_INT == 0x7
        #define XMSS_OID "XMSSMT-SHA2_60/6_256"
        #define XMSS_SECRETKEYBYTES 24507
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 14824
    #elif XMSS_OID_INT == 0x8
        #define XMSS_OID "XMSSMT-SHA2_60/12_256"
        #define XMSS_SECRETKEYBYTES 38095
        #define XMSS_PUBLICKEYBYTES 64
        #define XMSS_SIGNBYTES 27688

    #else
        #error "Not supported XMSS_OID_INT"
    #endif

    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_REMAINING_SIG xmssmt_remaining_signatures
    #define XMSS_TOTAL_SIG xmssmt_total_signatures
#endif

#define CRYPTO_ALGNAME XMSS_OID

#define CRYPTO_SECRETKEYBYTES (XMSS_SECRETKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_PUBLICKEYBYTES (XMSS_PUBLICKEYBYTES + XMSS_OID_LEN)
#define CRYPTO_BYTES XMSS_SIGNBYTES

#endif