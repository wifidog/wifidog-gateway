#!/usr/bin/env bash


function main {
    if [[ -z "$BUILD_TYPE" ]]; then
        echo "BUILD_TYPE not set. Bye."
        exit 1
    fi

    if [[ "$BUILD_TYPE" == "normal" ]]; then

        echo "Running Wifidog configure"
        ./configure $@

    elif [[ "$BUILD_TYPE" == "full" ]]; then
        if [[ -z "$CYASSL" || -z "$LIBCAP" || -z "$LIBATTR" ]]; then
            echo "Make sure that CYASSL, LIBCAP and LIBATTR are set."
            exit 1
        fi
        mkdir -p dependencies-src || true
        mkdir -p dependencies-installed || true
        # reset CFLAGS because some dependencies generate warnings
        OLD_CFLAGS="${CFLAGS}"
        OLD_CXXFLAGS="${CXXFLAGS}"
        OLD_LDFLAGS="${LDFLAGS}"
        CUR=`pwd`
        export CFLAGS="-I${CUR}/dependencies-installed/include/"
        export CXXFLAGS="-I${CUR}/dependencies-installed/include/"
        export LDFLAGS="-L${CUR}/dependencies-installed/lib/"
        build_cyassl
        build_libattr
        build_libcap
        echo "Running Wifidog configure"
        export CFLAGS="${OLD_CFLAGS} ${CFLAGS}"
        export CXXFLAGS="${OLD_CXXFLAGS} ${LDFLAGS}"
        export LDFLAGS="${OLD_LDFLAGS} ${LDFLAGS}"
        ./configure --enable-cyassl --enable-libcap $@
    else
        echo "Unknow BUILD_TYPE $BUILD_TYPE"
        exit 1
    fi

}

function build_cyassl {
    # TODO: changing $CYASSL version number will not invalidate this check
    # Need to remove full cache in travis interface if we want to upgrade
    # CyaSSL
    CUR=`pwd`
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
}

function build_libcap {
    CUR=`pwd`
    if [[ ! -f dependencies-installed/usr/include/sys/capability.h ]]; then
        echo "Cached libcap not found. Installing."
        cd dependencies-src
        if [[ -f libcap-${LIBCAP}/Makefile ]]; then
            echo "Found cached libcap package"
        else
            echo "No cache, downloading libcap"
            wget https://www.kernel.org/pub/linux/libs/security/linux-privs/libcap2/libcap-${LIBCAP}.tar.gz \
                -O libcap-${LIBCAP}.tar.gz
            tar -xvzf libcap-${LIBCAP}.tar.gz
        fi
        cd libcap-${LIBCAP}
        echo "Content of libcap-${LIBCAP}"
        ls
        echo "Running libcap make install"
        make install DESTDIR="$CUR"/dependencies-installed/ IPATH="${CFLAGS} -fPIC -I\$(topdir)/libcap/include/uapi -I\$(topdir)/libcap/include" LDFLAGS=${LDFLAGS} RAISE_SETFCAP=no
        cd "$CUR"
    else
        echo "Cached libcap install found."
    fi

}

function build_libattr {
    CUR=`pwd`
    if [[ ! -f dependencies-installed/include/attr/libattr.h ]]; then
        echo "Cached libattr not found. Installing."
        cd dependencies-src
        if [[ -f libattr-${LIBATTR}/configure ]]; then
            echo "Found cached libattr package"
        else
            echo "No cache, downloading libattr"
            wget http://download.savannah.gnu.org/releases/attr/attr-${LIBATTR}.src.tar.gz \
                -O attr-${LIBATTR}.tar.gz
            tar -xvzf attr-${LIBATTR}.tar.gz
        fi
        cd attr-${LIBATTR}
        echo "Content of attr-${LIBATTR}"
        ls
        echo "Running attr configure"
        ./configure --prefix="$CUR"/dependencies-installed/
        echo "Running attr make install"
        make install install-dev install-lib
        cd $CUR
    else
        echo "Cached attr install found."
    fi
}

main
