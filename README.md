FeBGP
=====

This is a very basic BGP implementation to let a physical server announce an IPv6 prefix to a BGP fabric.

FeBGP will most likely be used via its Rust API. But this code also includes a main function, that allows you to execute
FeBGP from the CLI:

    ./febgp \
        --asn 65000 \
        --hold-time 9 \
        --router-id 1.2.3.4 \
        --neighbor 2001:db8::1 \
        --neighbor interface:eth0

### License

FeBGP is licensed under [Apache License v2.0](LICENSE).