FROM svftools/svf:latest

# Install wllvm using pipx
RUN apt-get update && \
    apt-get install -y pipx python3-tomli python3.10-venv && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN pipx install wllvm

ENV PATH="/home/SVF-tools/.local/bin:${PATH}"
ENV LLVM_COMPILER=clang

# Download and extract recutils v1.9
WORKDIR /home/SVF-tools
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/recutils/recutils-1.9.tar.gz && \
    tar -xzf recutils-1.9.tar.gz && \
    rm recutils-1.9.tar.gz

WORKDIR /home/SVF-tools/recutils-1.9

# Install build dependencies (file for extract-bc)
RUN apt-get update && \
    apt-get install -y file && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Configure with static linking and WLLVM
# Add -Wno-error=implicit-function-declaration to handle older code
RUN CC=wllvm \
    CFLAGS="-g -O0 -Xclang -disable-llvm-passes -Wno-error=implicit-function-declaration" \
    LDFLAGS="-static -Wl,--allow-multiple-definition" \
    FORCE_UNSAFE_CONFIGURE=1 \
    ./configure --disable-shared

# Build recutils (use sequential build to avoid dependency issues)
RUN make

# Create bc directory and extract bitcode files
# Main binaries: recinf, recsel, recins, recdel, recset, recfix, recfmt, csv2rec, rec2csv
RUN mkdir -p ~/bc && \
    for bin in utils/recinf utils/recsel utils/recins utils/recdel utils/recset utils/recfix utils/recfmt utils/csv2rec utils/rec2csv; do \
        if [ -f "$bin" ] && [ -x "$bin" ]; then \
            extract-bc "$bin" && \
            mv "${bin}.bc" ~/bc/ 2>/dev/null || true; \
        fi; \
    done

# Verify that bc files were created
RUN ls -la ~/bc/
