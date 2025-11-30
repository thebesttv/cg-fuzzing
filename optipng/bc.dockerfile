FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract optipng 0.7.8
WORKDIR /home/SVF-tools
RUN wget https://sourceforge.net/projects/optipng/files/OptiPNG/optipng-0.7.8/optipng-0.7.8.tar.gz && \
    tar -xzf optipng-0.7.8.tar.gz && \
    rm optipng-0.7.8.tar.gz

WORKDIR /home/SVF-tools/optipng-0.7.8

# Configure and build with WLLVM for bitcode extraction
# optipng uses a custom configure script, not autotools
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc src/optipng/optipng && \
    mv src/optipng/optipng.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
