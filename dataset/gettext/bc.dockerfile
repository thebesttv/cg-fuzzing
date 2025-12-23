FROM thebesttv/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract gettext v0.23.1

# Create working directory and save project metadata
WORKDIR /work
RUN echo "project: gettext" > /work/proj && \
    echo "version: 0.23.1" >> /work/proj && \
    echo "source: https://ftpmirror.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz" >> /work/proj

# Download source code and extract to /work/build
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftpmirror.gnu.org/gnu/gettext/gettext-0.23.1.tar.gz && \
    tar -xzf gettext-0.23.1.tar.gz && \
    mv gettext-0.23.1 build && \
    rm gettext-0.23.1.tar.gz

WORKDIR /work/build

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file autoconf automake libtool bison flex && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CXX=wllvm++ \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    CXXFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --disable-java --disable-native-java --without-emacs

# Build gettext
RUN make -j$(nproc)

# Create bc directory and extract bitcode files from main binaries
RUN mkdir -p /work/bc && \
    for bin in gettext-tools/src/msgfmt gettext-tools/src/msgunfmt gettext-tools/src/xgettext gettext-tools/src/msgmerge gettext-tools/src/msgcat; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" /work/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la /work/bc/
