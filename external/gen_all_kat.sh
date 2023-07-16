#!/bin/bash

# Only run on MAC
cmd="clang -Wall -O3 -Wextra -Wpedantic  -o test/sign_gen_NIST_KAT_fast params.c hash.c hash_address.c wots.c xmss.c xmss_core_fast.c xmss_commons.c utils.c test/sign_gen_NIST_KAT.c sign.c -L/Users/ductri.nguyen/Work/openssl/oqs/lib -I/Users/ductri.nguyen/Work/openssl/oqs/include/ -L/opt/homebrew/opt/openssl@1.1/lib -I/opt/homebrew/opt/openssl@1.1/include -lcrypto -loqs"

echo "XMSSMT=0"
for i in $(jot -w 0x%x 12 1);
do 
    echo "-DXMSS_OID_INT=${i}"
    new_cmd="${cmd} -DXMSSMT=0 -DXMSS_OID_INT=${i}"
    # Compile
    eval ${new_cmd}
    # Execute
    time test/sign_gen_NIST_KAT_fast
done

echo "XMSSMT=1"
for i in $(jot -w 0x%x 8 1);
do 
    echo "-DXMSS_OID_INT=${i}"
    new_cmd="${cmd} -DXMSSMT=1 -DXMSS_OID_INT=${i}"
    # Compile
    eval ${new_cmd}
    # Execute
    time test/sign_gen_NIST_KAT_fast
done