FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libidn 1.42
WORKDIR /home/SVF-tools
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/libidn/libidn-1.42.tar.gz && \
    tar -xzf libidn-1.42.tar.gz && \
    rm libidn-1.42.tar.gz

WORKDIR /home/SVF-tools/libidn-1.42

# Configure with WLLVM and static linking
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

# Build libidn
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/idn && \
    mv src/idn.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
