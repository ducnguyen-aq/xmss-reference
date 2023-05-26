# XMSS reference code

## Instructions

### Generate KATs

Inside `external` directory, you can run and generate KATs by:

```shell
$ make kat
```

It will generate KATs for the smallest parameter `XMSS-SHA2_10_256`

Note: The KATs file should be exactly identical everytime you run. 

Here is the output hashes of KATs for parameter `XMSS-SHA2_10_256`:

```shell
$ sha256sum *.rsp *.req

42c0b952fa7961731f99c0c8ba12c00577e4a44bc8d2f21d95ce65da81e2b52c  PQCsignKAT_XMSS-SHA2_10_256.rsp
4bfce59088017eac8da37e55d70c799d3ea6b40573c48b8557b6750074246e78  PQCsignKAT_XMSS-SHA2_10_256.req
3ab550ced911b351a90dfb9de752160abe8900ad3a5e5a25f3ae465b3e19955d  PQCsignKAT_XMSS-SHA2_10_256_fast.rsp
66018d78afda14eab0604eb2867ba12bb65a7e2accb26a7b3559d0068bea3808  PQCsignKAT_XMSS-SHA2_10_256_fast.req
```

### Benchmark 

Inside `external` directory, you can run benchmark:

```shell
$ make bench
```

It will execute two versions of XMSS: the `small` secret key and `large` (`_fast` parameter) secret key. 

In my code, the original parameter name is the default option: `small`.
To run the `large` or `_fast` option, instead of build with `xmss_core.c`, I select `xmss_core_fast.c` in `Makefile`.

When secret key is not planned to be exported, it's better to use `large` secret key for the gain of performance. 

For the smallest parameter `XMSS-SHA2_10_256`, the example output of the `small` and `large` verions are:

```shell

XMSS-SHA2_10_256 Benchmark:
Keygen: 849855.983000 us
Sign:   median        : 846433 us
        average       : 848031 us

Verify: median        : 438 us
        average       : 443 us

XMSS-SHA2_10_256_fast Benchmark:
Keygen: 847504.134000 us
Sign:   median        : 1284 us
        average       : 1863 us

Verify: median        : 435 us
        average       : 450 us
```

The performance gain for Sign operation is significant. As shown in the example output above, the `fast` version is `455 times faster` than the default version of XMSS for parameter `XMSS-SHA2_10_256`.

