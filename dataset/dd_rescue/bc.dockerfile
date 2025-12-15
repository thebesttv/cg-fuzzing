FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract dd_rescue v1.99.22
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 http://www.garloff.de/kurt/linux/ddrescue/dd_rescue-1.99.22.tar.bz2 && \
    tar -xjf dd_rescue-1.99.22.tar.bz2 && \
    rm dd_rescue-1.99.22.tar.bz2

WORKDIR /home/SVF-tools/dd_rescue-1.99.22

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file libssl-dev autoconf && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure and build with WLLVM
RUN autoreconf -fi && ./configure

RUN make CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    dd_rescue

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc dd_rescue && \
    mv dd_rescue.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
