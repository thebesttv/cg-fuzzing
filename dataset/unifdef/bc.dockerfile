FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract unifdef 2.12
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp2.osuosl.org/pub/blfs/12.4/u/unifdef-2.12.tar.gz && \
    tar -xzf unifdef-2.12.tar.gz && \
    rm unifdef-2.12.tar.gz

WORKDIR /home/SVF-tools/unifdef-2.12

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build unifdef with static linking and WLLVM
RUN make CC=wllvm CFLAGS="-g -O0 -Xclang -disable-llvm-passes" LDFLAGS="-static -Wl,--allow-multiple-definition"

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc unifdef && \
    mv unifdef.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
