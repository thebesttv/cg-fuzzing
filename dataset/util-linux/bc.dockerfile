FROM thebesttv/svf:latest

RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

WORKDIR /home/SVF-tools
RUN wget https://github.com/util-linux/util-linux/archive/refs/tags/v2.40.2.tar.gz && \
    tar -xzf v2.40.2.tar.gz && \
    mv v2.40.2 build && \
    rm v2.40.2.tar.gz

WORKDIR /work/build

RUN apt-get update && \
    apt-get install -y file autoconf automake autopoint libtool pkg-config gettext bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN ./autogen.sh

RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static --disable-all-programs \
        --enable-libuuid --enable-uuidgen

RUN make -j$(nproc)

RUN mkdir -p /work/bc && \
    find . -type f -executable -name "uuidgen" -o -name "uuidparse" -o -name "test_uuid" | while read bin; do \
        if [ -f "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            basename_bc=$(basename "$bin").bc && \
            mv "${bin}.bc" /work/bc/"$basename_bc" 2>/dev/null || true; \
        fi; \
    done

RUN ls -la /work/bc/
