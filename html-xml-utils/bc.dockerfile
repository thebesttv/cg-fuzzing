FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract html-xml-utils v8.6
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://www.w3.org/Tools/HTML-XML-utils/html-xml-utils-8.6.tar.gz && \
    tar -xzf html-xml-utils-8.6.tar.gz && \
    rm html-xml-utils-8.6.tar.gz

WORKDIR /home/SVF-tools/html-xml-utils-8.6

# Install build dependencies
RUN apt-get update && \
    apt-get install -y file flex bison && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ./configure --disable-shared

# Build
RUN make -j$(nproc)

# Create bc directory and extract bitcode files for main tools
RUN mkdir -p ~/bc && \
    for bin in hxnormalize hxselect hxpipe hxclean hxcount; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
