FROM svftools/svf:latest

# Install wllvm using pip3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages wllvm

ENV LLVM_COMPILER=clang

# Download and extract stress-ng v0.18.05
WORKDIR /home/SVF-tools
RUN wget https://github.com/ColinIanKing/stress-ng/archive/V0.18.05.tar.gz && \
    tar -xzf V0.18.05.tar.gz && \
    rm V0.18.05.tar.gz

WORKDIR /home/SVF-tools/stress-ng-0.18.05

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file libaio-dev libapparmor-dev libattr1-dev libbsd-dev libcap-dev libgcrypt-dev libipsec-mb-dev libjudy-dev libkeyutils-dev libkmod-dev libsctp-dev libxxhash-dev zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build with static linking and WLLVM
# Note: stress-ng uses make directly, no configure
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    make -j$(nproc) STATIC=1

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    if [ -f "stress-ng" ] && [ -x "stress-ng" ] && file "stress-ng" | grep -q "ELF"; then \
        extract-bc stress-ng && \
        mv stress-ng.bc ~/bc/ 2>/dev/null || true; \
    fi

# Verify that bc files were created
RUN ls -la ~/bc/
