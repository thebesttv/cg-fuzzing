FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract minicom v2.9
WORKDIR /home/SVF-tools
RUN wget https://salsa.debian.org/minicom-team/minicom/-/archive/2.9/minicom-2.9.tar.gz && \
    tar -xzf minicom-2.9.tar.gz && \
    rm minicom-2.9.tar.gz

WORKDIR /home/SVF-tools/minicom-2.9

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file autoconf automake gettext libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Run autogen to generate configure
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build minicom
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/minicom && \
    mv src/minicom.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
