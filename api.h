#ifndef API_H
#define API_H

#include <stdint.h>
/*************************************************
 * Name:        XMSS_crypto_sign_keypair
 *
 * Description: Generates public and private key.
 *
 * Arguments:   - uint8_t *pk: pointer to output public key (allocated
 *                             array of CRYPTO_PUBLIC_KEY bytes)
 *              - uint8_t *sk: pointer to output private key (allocated
 *                             array of CRYPTO_SECRET_KEY bytes)
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk);

/*************************************************
 * Name:        XMSS_crypto_sign
 *
 * Description: Computes signature.
 *
 * Arguments:   - uint8_t *sm:   pointer to output signature (of length CRYPTO_BYTES)
 *              - uint64_t *smlen: pointer to output length of signature
 *              - uint8_t *m:     pointer to message to be signed
 *              - uint64_t mlen:    length of message
 *              - uint8_t *sk:    pointer to bit-packed secret key
 *
 * Returns 0 (success), -1 otherwise
 **************************************************/
int crypto_sign(unsigned char *sm, uint64_t *smlen,
                const unsigned char *m, uint64_t mlen, unsigned char *sk);

/*************************************************
 * Name:        XMSS_crypto_sign_open
 *
 * Description: Verify signed message.
 *
 * Arguments:   
 *              - uint8_t *m: pointer to output message (allocated
 *                            array with smlen bytes), can be equal to sm
 *              - uint64_t *mlen: pointer to output length of message
 *              - uint8_t *sm: pointer to signed message
 *              - uint64_t smlen: length of signed message
 *              - uint8_t *pk: pointer to bit-packed public key
 *
 * Returns 0 if signed message could be verified correctly and -1 otherwise
 **************************************************/
int crypto_sign_open(unsigned char *m, uint64_t *mlen,
                     const unsigned char *sm, uint64_t smlen, const unsigned char *pk);

/*************************************************
 * Name:        XMSS_crypto_remaining_signatures
 *
 * Description: Return number of signatures left
 *
 * Arguments:   - uint64_t *remain: remaining signatures
 *              - uint8_t *sk: pointer to bit-packed private key
 *
 * Returns 0 (sucess), -1 otherwise
 **************************************************/
int crypto_remaining_signatures(uint64_t *remain, const unsigned char *sk);

#endif 

