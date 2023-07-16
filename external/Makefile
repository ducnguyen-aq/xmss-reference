CC = clang
SHELL := /bin/bash

LIBOQS = -L/Users/ductri.nguyen/Work/openssl/oqs/lib -I/Users/ductri.nguyen/Work/openssl/oqs/include/
OPENSSL = -L/opt/homebrew/opt/openssl@1.1/lib -I/opt/homebrew/opt/openssl@1.1/include

CFLAGS = -Wall -O3 -Wextra -Wpedantic #-fsanitize-address-use-after-return=always -fsanitize=address
LDLIBS =  $(LIBOQS) $(OPENSSL) -lcrypto -loqs

SOURCES = params.c hash.c hash_address.c wots.c xmss.c xmss_core.c xmss_commons.c utils.c
HEADERS = params.h hash.h hash_address.h wots.h xmss.h xmss_core.h xmss_commons.h utils.h

SOURCES_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(SOURCES))
HEADERS_FAST = $(subst xmss_core.c,xmss_core_fast.c,$(HEADERS))

TESTS = test/wots \
		test/oid \
		test/speed \
		test/xmss_determinism \
		test/xmss \
		test/xmss_fast \
		test/xmssmt \
		test/xmssmt_fast \
		test/maxsigsxmss \
		test/maxsigsxmssmt

UI = ui/xmss_keypair \
	 ui/xmss_sign \
	 ui/xmss_open \
	 ui/xmssmt_keypair \
	 ui/xmssmt_sign \
	 ui/xmssmt_open \
	 ui/xmss_keypair_fast \
	 ui/xmss_sign_fast \
	 ui/xmss_open_fast \
	 ui/xmssmt_keypair_fast \
	 ui/xmssmt_sign_fast \
	 ui/xmssmt_open_fast

KATS = test/sign_gen_NIST_KAT_fast \
		test/sign_test_NIST_KAT_fast

BENCH = test/sign_bench_fast

INFO = test/print_keysize_signature_size

all: info kat bench

tests: $(TESTS)
ui: $(UI)
kat: $(KATS)
bench: $(BENCH)
info: $(INFO)

test: $(TESTS:=.exec)

.PHONY: clean test

test/print_keysize_signature_size: test/print_keysize_signature_size.c
	$(CC) $(CFLAGS) -o $@ hash.c hash_address.c wots.c utils.c xmss_commons.c xmss_core_fast.c params.c $< $(LDLIBS)
	./$@

test/%.exec: test/%
	@$<

test/sign_KAT_fast: sign.c sign_params.h sign.h test/sign_KAT.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) test/sign_KAT.c $< $(LDLIBS)

test/sign_gen_NIST_KAT_fast: sign.c sign_params.h sign.h test/sign_gen_NIST_KAT.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) test/sign_gen_NIST_KAT.c $< $(LDLIBS)
	time $@

test/sign_test_NIST_KAT_fast: sign.c sign_params.h sign.h test/sign_test_NIST_KAT.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) test/sign_test_NIST_KAT.c $< $(LDLIBS)
	time $@

test/sign_bench_fast: sign.c sign_params.h sign.h test/sign_bench.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) test/sign_bench.c  $< $(LDLIBS)
	$@

test/xmss_fast: test/xmss.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSS_SIGNATURES=1024 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/xmss: test/xmss.c $(SOURCES)  $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/xmssmt_fast: test/xmss.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSSMT -DXMSS_SIGNATURES=1024 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/xmssmt: test/xmss.c $(SOURCES)  $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

test/speed: test/speed.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSS_SIGNATURES=64 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/speedmt: test/speed.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSSMT -DXMSS_SIGNATURES=64 $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/vectors: test/vectors.c $(SOURCES)  $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)
	
test/maxsigsxmss: test/xmss_max_signatures.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

test/maxsigsxmssmt: test/xmss_max_signatures.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)
	
test/%: test/%.c $(SOURCES)  $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmss_%_fast: ui/%.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmssmt_%_fast: ui/%.c $(SOURCES_FAST)  $(HEADERS_FAST)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES_FAST) $< $(LDLIBS)

ui/xmss_%: ui/%.c $(SOURCES)  $(HEADERS)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

ui/xmssmt_%: ui/%.c $(SOURCES)  $(HEADERS)
	$(CC) -DXMSSMT $(CFLAGS) -o $@ $(SOURCES) $< $(LDLIBS)

clean:
	-$(RM) $(TESTS)
	-$(RM) $(KATS)
	-$(RM) $(BENCH)
	-$(RM) $(INFO)
	-$(RM) *.rsp *.req
	-$(RM) test/vectors
	-$(RM) $(UI)
