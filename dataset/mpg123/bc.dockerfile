FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract mpg123 v1.32.7
WORKDIR /home/SVF-tools
RUN wget https://downloads.sourceforge.net/project/mpg123/mpg123/1.32.7/mpg123-1.32.7.tar.bz2 && \
    tar -xjf mpg123-1.32.7.tar.bz2 && \
    rm mpg123-1.32.7.tar.bz2

WORKDIR /home/SVF-tools/mpg123-1.32.7

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Disable audio output modules for simpler static linking
RUN CC=wllvm \
    CFLAGS="-g -O0" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared --enable-static --with-audio=dummy

# Build mpg123
RUN make -j$(nproc)

# Create bc directory and extract bitcode files
RUN mkdir -p ~/bc && \
    for bin in src/mpg123 src/out123; do \
        if [ -f "$bin" ] && [ -x "$bin" ] && file "$bin" | grep -q "ELF"; then \
            extract-bc "$bin" && \
            basename_bc=$(basename "$bin").bc && \
            mv "${bin}.bc" ~/bc/"${basename_bc}" 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
