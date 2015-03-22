#!/usr/bin/env bash

if [[ -z "$BUILD_TYPE" ]]; then
    echo "BUILD_TYPE not set. Bye."
    exit 1
fi

if [[ "$BUILD_TYPE" == "normal" ]]; then

    echo "Running Wifidog configure"
    ./configure $@

elif [[ "$BUILD_TYPE" == "cyassl" ]]; then
    if [[ -z "$CYASSL" ]]; then
        echo "CYASSL not set."
        exit 1
    fi
    CUR=`pwd`
    mkdir -p dependencies-src || true
    mkdir -p dependencies-installed || true
    if [[ ! -f dependencies-installed/include/cyassl/ssl.h ]]; then
        echo "Cached CyaSSL install not found. Installing."
        cd dependencies-src
        # Check if travis cache is there
        if [[ -f cyassl-${CYASSL}/autogen.sh ]]; then
            echo "Found cached CyaSSL package"
        else
            echo "No cache, downloading CyaSSL"
            wget https://github.com/cyassl/cyassl/archive/v${CYASSL}.tar.gz \
                -O cyassl-${CYASSL}.tar.gz
            tar -xzf cyassl-${CYASSL}.tar.gz
        fi
        cd cyassl-${CYASSL}
        echo "Content of cyassl-${CYASSL}:"
        ls
        echo "Running CyaSSL autogen.sh"
        ./autogen.sh
        echo "Running CyaSSL configure"
        ./configure --prefix="$CUR"/dependencies-installed/ --enable-ecc
        # make will pick up the cached object files - real savings
        # happen here
        echo "Running CyaSSL make"
        make
        echo "Running CyaSSL make install"
        make install
        cd "$CUR"
    else
        echo "Cached CyaSSL install found."
    fi
    echo "Running Wifidog configure"
    export CFLAGS="-I${CUR}/dependencies-installed/include/"
    export LDFLAGS="-L${CUR}/dependencies-installed/lib/"
    ./configure --enable-cyassl $@
else
    echo "Unknow BUILD_TYPE $BUILD_TYPE"
    exit 1
fi
