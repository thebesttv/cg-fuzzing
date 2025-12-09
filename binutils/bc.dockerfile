FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract binutils v2.43.1
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/binutils/binutils-2.43.1.tar.gz && \
    tar -xzf binutils-2.43.1.tar.gz && \
    rm binutils-2.43.1.tar.gz

WORKDIR /home/SVF-tools/binutils-2.43.1

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file texinfo zlib1g-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Enable only a subset of tools to speed up build
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure \
        --disable-shared \
        --enable-static \
        --disable-werror \
        --disable-gdb \
        --disable-libdecnumber \
        --disable-readline \
        --disable-sim

# Build binutils
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from main tools
RUN mkdir -p ~/bc && \
    for tool in binutils/readelf binutils/objdump binutils/size \
                binutils/strings binutils/nm-new binutils/strip-new \
                binutils/objcopy binutils/addr2line binutils/ar \
                binutils/ranlib binutils/elfedit; do \
        if [ -f "$tool" ] && [ -x "$tool" ]; then \
            extract-bc "$tool" && \
            bcname=$(basename "$tool" | sed 's/-new//').bc && \
            mv "${tool}.bc" ~/bc/"$bcname" 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
