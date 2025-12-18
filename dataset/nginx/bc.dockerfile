FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract nginx v1.29.4
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://nginx.org/download/nginx-1.29.4.tar.gz && \
    tar -xzf nginx-1.29.4.tar.gz && \
    rm nginx-1.29.4.tar.gz

WORKDIR /home/SVF-tools/nginx-1.29.4

# Install build dependencies (file for extract-bc, libpcre for nginx)
RUN apt-get update && \
    apt-get install -y file libpcre3-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# nginx requires --with-ld-opt for linker flags
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    ./configure --with-cc-opt="-g -O0 -Xclang -disable-llvm-passes" \
                --with-ld-opt="-static -Wl,--allow-multiple-definition" \
                --without-http_rewrite_module \
                --without-http_gzip_module

# Build nginx
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc objs/nginx && \
    mv objs/nginx.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
