FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract entr 5.6
WORKDIR /home/SVF-tools
RUN wget https://github.com/eradman/entr/archive/refs/tags/5.6.tar.gz && \
    tar -xzf 5.6.tar.gz && \
    rm 5.6.tar.gz

WORKDIR /home/SVF-tools/entr-5.6

# Configure entr (uses simple configure script)
RUN ./configure

# Build entr with WLLVM and static linking
RUN make CC=wllvm CFLAGS="-g -O0" LDFLAGS="-static -Wl,--allow-multiple-definition" -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc entr && \
    mv entr.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
