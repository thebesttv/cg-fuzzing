FROM aflplusplus/aflplusplus:latest
RUN apt-get update && apt-get install -y wget m4 && apt-get clean
RUN mkdir -p /out
WORKDIR /src
RUN wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz && tar -xzf groff-1.23.0.tar.gz && rm groff-1.23.0.tar.gz
WORKDIR /src/groff-1.23.0
RUN CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-O2" CXXFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" ./configure --disable-shared && make -j$(nproc)
RUN cp groff /out/groff
WORKDIR /src
RUN rm -rf groff-1.23.0 && wget --inet4-only --tries=3 --retry-connrefused --waitretry=5 https://ftp.gnu.org/gnu/groff/groff-1.23.0.tar.gz && tar -xzf groff-1.23.0.tar.gz && rm groff-1.23.0.tar.gz
WORKDIR /src/groff-1.23.0
RUN CC=afl-clang-lto CXX=afl-clang-lto++ CFLAGS="-O2" CXXFLAGS="-O2" LDFLAGS="-static -Wl,--allow-multiple-definition" AFL_LLVM_CMPLOG=1 ./configure --disable-shared && AFL_LLVM_CMPLOG=1 make -j$(nproc)
RUN cp groff /out/groff.cmplog
COPY dataset/groff/fuzz/dict /out/dict
COPY dataset/groff/fuzz/in /out/in
COPY dataset/groff/fuzz/fuzz.sh /out/fuzz.sh
COPY dataset/groff/fuzz/whatsup.sh /out/whatsup.sh
WORKDIR /out
RUN ls -la /out/groff /out/groff.cmplog && file /out/groff
CMD ["/bin/bash", "-c", "echo 'Run ./fuzz.sh to start fuzzing groff'"]
