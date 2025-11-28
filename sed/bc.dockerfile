FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract sed 4.9
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/sed/sed-4.9.tar.gz && \
    tar -xzf sed-4.9.tar.gz && \
    rm sed-4.9.tar.gz

WORKDIR /home/SVF-tools/sed-4.9

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build sed
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc sed/sed && \
    mv sed/sed.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
