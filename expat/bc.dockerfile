FROM svftools/svf:latest

# 1. Install WLLVM
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# 2. Download expat source code
WORKDIR /home/SVF-tools
RUN wget https://github.com/libexpat/libexpat/releases/download/R_2_7_3/expat-2.7.3.tar.gz && \
    tar -xzf expat-2.7.3.tar.gz && \
    rm expat-2.7.3.tar.gz

WORKDIR /home/SVF-tools/expat-2.7.3

# 3. Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 4. Configure and build expat with WLLVM (Autotools project)
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --without-docbook

RUN make -j$(nproc)

# 5. Extract bitcode file for xmlwf
RUN mkdir -p ~/bc && \
    extract-bc xmlwf/xmlwf && \
    mv xmlwf/xmlwf.bc ~/bc/

# 6. Verify
RUN ls -la ~/bc/
