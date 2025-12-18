FROM thebesttv/svf:latest

RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

WORKDIR /home/SVF-tools
RUN wget https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.tar.gz && \
    tar -xzf libssh2-1.11.1.tar.gz && \
    rm libssh2-1.11.1.tar.gz

WORKDIR /home/SVF-tools/libssh2-1.11.1

RUN apt-get update && \
    apt-get install -y file cmake libssl-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build static versions of openssl and zlib for static linking
RUN cd /tmp && \
    wget https://www.openssl.org/source/openssl-3.0.15.tar.gz && \
    tar -xzf openssl-3.0.15.tar.gz && \
    cd openssl-3.0.15 && \
    ./config no-shared --prefix=/usr/local/ssl && \
    make -j$(nproc) && \
    make install && \
    cd /tmp && rm -rf openssl-3.0.15*

RUN cd /tmp && \
    wget https://zlib.net/zlib-1.3.1.tar.gz && \
    tar -xzf zlib-1.3.1.tar.gz && \
    cd zlib-1.3.1 && \
    ./configure --prefix=/usr/local --static && \
    make -j$(nproc) && \
    make install && \
    cd /tmp && rm -rf zlib-1.3.1*

RUN mkdir build && cd build && \
    CC=wllvm CXX=wllvm++ \
    cmake .. \
        -DCMAKE_C_FLAGS="-g -O0 -Xclang -disable-llvm-passes" \
        -DCMAKE_EXE_LINKER_FLAGS="-static -Wl,--allow-multiple-definition" \
        -DOPENSSL_ROOT_DIR=/usr/local/ssl \
        -DOPENSSL_USE_STATIC_LIBS=ON \
        -DZLIB_ROOT=/usr/local \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_EXAMPLES=ON \
        -DBUILD_TESTING=OFF

WORKDIR /home/SVF-tools/libssh2-1.11.1/build
RUN make -j$(nproc)

RUN mkdir -p ~/bc && \
    for bin in example/*; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

RUN ls -la ~/bc/
