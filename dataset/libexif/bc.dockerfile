FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract libexif v0.6.25
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/libexif/releases/download/v0.6.25/libexif-0.6.25.tar.gz && \
    tar -xzf libexif-0.6.25.tar.gz && \
    rm libexif-0.6.25.tar.gz

WORKDIR /home/SVF-tools/libexif-0.6.25

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file gettext && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build libexif as static library with WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared --enable-static

RUN make -j$(nproc)
RUN make install

# Download and build exif CLI tool
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://github.com/libexif/exif/releases/download/exif-0_6_22-release/exif-0.6.22.tar.gz && \
    tar -xzf exif-0.6.22.tar.gz && \
    rm exif-0.6.22.tar.gz

WORKDIR /home/SVF-tools/exif-0.6.22

# Install popt for exif CLI
RUN apt-get update && \
    apt-get install -y libpopt-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Build exif CLI with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -I/usr/local/include" \
    LDFLAGS="-static -Wl,--allow-multiple-definition -L/usr/local/lib" \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" \
    POPT_CFLAGS="-I/usr/include" \
    POPT_LIBS="-lpopt" \
    ./configure --disable-shared

RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    extract-bc exif/exif && \
    mv exif/exif.bc ~/bc/

# Verify that bc files were created
RUN ls -la ~/bc/
