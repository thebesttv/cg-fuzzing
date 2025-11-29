FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget libreadline-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract Lua 5.4.8 (same version as bc.dockerfile)
WORKDIR /src
RUN wget --tries=3 --retry-connrefused --waitretry=5 https://www.lua.org/ftp/lua-5.4.8.tar.gz && \
    tar -xzf lua-5.4.8.tar.gz && \
    rm lua-5.4.8.tar.gz

WORKDIR /src/lua-5.4.8

# Build Lua with afl-clang-lto for fuzzing (main target binary)
# Use static linking
RUN make -j$(nproc) \
    CC=afl-clang-lto \
    MYCFLAGS="-O2" \
    MYLDFLAGS="-static -Wl,--allow-multiple-definition" \
    linux

# Install the lua binary
RUN cp src/lua /out/lua

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf lua-5.4.8 && \
    wget --tries=3 --retry-connrefused --waitretry=5 https://www.lua.org/ftp/lua-5.4.8.tar.gz && \
    tar -xzf lua-5.4.8.tar.gz && \
    rm lua-5.4.8.tar.gz

WORKDIR /src/lua-5.4.8

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc) \
    CC=afl-clang-lto \
    MYCFLAGS="-O2" \
    MYLDFLAGS="-static -Wl,--allow-multiple-definition" \
    linux

# Install CMPLOG binary
RUN cp src/lua /out/lua.cmplog

# Copy fuzzing resources
COPY lua/fuzz/dict /out/dict
COPY lua/fuzz/in /out/in
COPY lua/fuzz/fuzz.sh /out/fuzz.sh
COPY lua/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/lua /out/lua.cmplog && \
    file /out/lua && \
    /out/lua -v

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing Lua'"]
