FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract dos2unix 7.5.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget "https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.2/dos2unix-7.5.2.tar.gz" && \
    tar -xzf dos2unix-7.5.2.tar.gz && \
    rm dos2unix-7.5.2.tar.gz

WORKDIR /src/dos2unix-7.5.2

# Build dos2unix with afl-clang-lto for fuzzing (main target binary)
RUN make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ENABLE_NLS=

# Install the dos2unix binary
RUN cp dos2unix /out/dos2unix

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf dos2unix-7.5.2 && \
    wget "https://downloads.sourceforge.net/project/dos2unix/dos2unix/7.5.2/dos2unix-7.5.2.tar.gz" && \
    tar -xzf dos2unix-7.5.2.tar.gz && \
    rm dos2unix-7.5.2.tar.gz

WORKDIR /src/dos2unix-7.5.2

RUN AFL_LLVM_CMPLOG=1 make CC=afl-clang-lto \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    ENABLE_NLS=

# Install CMPLOG binary
RUN cp dos2unix /out/dos2unix.cmplog

# Copy fuzzing resources
COPY dos2unix/fuzz/dict /out/dict
COPY dos2unix/fuzz/in /out/in
COPY dos2unix/fuzz/fuzz.sh /out/fuzz.sh
COPY dos2unix/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/dos2unix /out/dos2unix.cmplog && \
    file /out/dos2unix && \
    /out/dos2unix --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing dos2unix'"]
