FROM thebesttv/svf:latest

# Install wllvm using pip3
RUN apt-get update && \
    apt-get install -y python3-pip && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages wllvm

ENV LLVM_COMPILER=clang

# Download and extract procps v4.0.4
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://gitlab.com/procps-ng/procps/-/archive/v4.0.4/procps-v4.0.4.tar.gz && \
    tar -xzf procps-v4.0.4.tar.gz && \
    rm procps-v4.0.4.tar.gz

WORKDIR /home/SVF-tools/procps-v4.0.4

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool gettext autopoint pkg-config libncurses-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Bootstrap the build system
RUN ./autogen.sh

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --disable-nls

# Build procps
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in src/ps/ps src/top/top src/free src/pgrep src/pkill src/pmap src/pwdx src/sysctl src/uptime src/vmstat src/w src/watch; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
