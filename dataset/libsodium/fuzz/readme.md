# libsodium Fuzzing Resources

## External Resources

- dict: Custom dictionary for crypto operations
- in/: Created initial seed inputs (empty, test data, zeros)

## Target Binary

Fuzzing `aead_chacha20poly1305` test program which exercises AEAD encryption/decryption with ChaCha20-Poly1305.

## Usage

```bash
docker build -f libsodium/fuzz.dockerfile -t libsodium-fuzz .
docker run -it --rm libsodium-fuzz ./fuzz.sh
```

For parallel fuzzing:
```bash
docker run -it --rm libsodium-fuzz ./fuzz.sh -j 4
```

Monitor progress:
```bash
docker run -it --rm libsodium-fuzz ./whatsup.sh
```
