#!/usr/bin/env bash

if [[ -z "$BUILD_TYPE" ]]; then
    echo "BUILD_TYPE not set. Bye."
    exit 1
fi

if [[ "$BUILD_TYPE" == "normal" ]]; then

    echo "Running Wifidog configure"
    ./configure $@

elif [[ "$BUILD_TYPE" == "wolfssl" ]]; then
    if [[ -z "$WOLFSSL" ]]; then
        echo "WOLFSSL not set."
        exit 1
    fi
    CUR=`pwd`
    mkdir -p dependencies-src || true
    mkdir -p dependencies-installed || true
    if [[ ! -f dependencies-installed/include/wolfssl/ssl.h ]]; then
        echo "Cached WolfSSL install not found. Installing."
        cd dependencies-src
        # Check if travis cache is there
        if [[ -f wolfssl-${WOLFSSL}/autogen.sh ]]; then
            echo "Found cached WolfSSL package"
        else
            echo "No cache, downloading WolfSSL"
            wget https://github.com/wolfSSL/wolfssl/archive/v${WOLFSSL}-stable.tar.gz \
                -O wolfssl-${WOLFSSL}.tar.gz
            tar -xzf wolfssl-${WOLFSSL}.tar.gz
        fi
        cd wolfssl-${WOLFSSL}
        echo "Content of wolfssl-${WOLFSSL}:"
        ls
        echo "Running WolfSSL autogen.sh"
        ./autogen.sh
        echo "Running WolfSSL configure"
        ./configure --prefix="$CUR"/dependencies-installed/ --enable-ecc
        # make will pick up the cached object files - real savings
        # happen here
        echo "Running WolfSSL make"
        make
        echo "Running WolfSSL make install"
        make install
        cd "$CUR"
    else
        echo "Cached WolfSSL install found."
    fi
    echo "Running Wifidog configure"
    export CFLAGS="-I${CUR}/dependencies-installed/include/"
    export LDFLAGS="-L${CUR}/dependencies-installed/lib/"
    ./configure --enable-wolfssl $@
else
    echo "Unknow BUILD_TYPE $BUILD_TYPE"
    exit 1
fi
