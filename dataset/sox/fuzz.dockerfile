FROM aflplusplus/aflplusplus:latest

# Install build dependencies
RUN apt-get update && \
    apt-get install -y wget bzip2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create output directory
RUN mkdir -p /out

# Download and extract SoX v14.4.2 (same version as bc.dockerfile)
WORKDIR /src
RUN wget https://downloads.sourceforge.net/project/sox/sox/14.4.2/sox-14.4.2.tar.bz2 && \
    tar -xjf sox-14.4.2.tar.bz2 && \
    rm sox-14.4.2.tar.bz2

WORKDIR /src/sox-14.4.2

# Build sox with afl-clang-lto for fuzzing (main target binary)
# Use static linking and disable external format libraries
RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static \
                --without-oss --without-alsa --without-ao --without-pulseaudio \
                --without-flac --without-mad --without-lame --without-opus \
                --without-png --without-ladspa --without-magic

RUN make -j$(nproc)

# Copy the sox binary
RUN cp src/sox /out/sox

# Build CMPLOG version for better fuzzing (comparison logging)
WORKDIR /src
RUN rm -rf sox-14.4.2 && \
    wget https://downloads.sourceforge.net/project/sox/sox/14.4.2/sox-14.4.2.tar.bz2 && \
    tar -xjf sox-14.4.2.tar.bz2 && \
    rm sox-14.4.2.tar.bz2

WORKDIR /src/sox-14.4.2

RUN CC=afl-clang-lto \
    CXX=afl-clang-lto++ \
    CFLAGS="-O2" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    AFL_LLVM_CMPLOG=1 \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static \
                --without-oss --without-alsa --without-ao --without-pulseaudio \
                --without-flac --without-mad --without-lame --without-opus \
                --without-png --without-ladspa --without-magic

RUN AFL_LLVM_CMPLOG=1 make -j$(nproc)

# Copy CMPLOG binary
RUN cp src/sox /out/sox.cmplog

# Copy fuzzing resources
COPY dataset/sox/fuzz/dict /out/dict
COPY dataset/sox/fuzz/in /out/in
COPY dataset/sox/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/sox/fuzz/whatsup.sh /out/whatsup.sh

WORKDIR /out

# Verify binaries are built
RUN ls -la /out/sox /out/sox.cmplog && \
    file /out/sox && \
    /out/sox --version

# Default command shows help
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing sox'"]
