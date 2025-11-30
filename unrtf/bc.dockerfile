FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract unrtf 0.21.10
WORKDIR /home/SVF-tools
RUN wget https://ftp.gnu.org/gnu/unrtf/unrtf-0.21.10.tar.gz && \
    tar -xzf unrtf-0.21.10.tar.gz && \
    rm unrtf-0.21.10.tar.gz

WORKDIR /home/SVF-tools/unrtf-0.21.10

# Configure and build with WLLVM for bitcode extraction
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/unrtf && \
    mv src/unrtf.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
