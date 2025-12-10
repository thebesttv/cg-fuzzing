FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract diction 1.11
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/diction/diction-1.11.tar.gz && \
    tar -xzf diction-1.11.tar.gz && \
    rm diction-1.11.tar.gz

WORKDIR /home/SVF-tools/diction-1.11

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure

# Build diction
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
# diction builds both 'diction' and 'style' binaries
RUN mkdir -p ~/bc && \
    extract-bc diction && \
    extract-bc style && \
    mv diction.bc ~/bc/ && \
    mv style.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
