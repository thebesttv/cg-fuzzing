# Candidate C Projects for Fuzzing (Not in current repo)

## Selection Criteria:
- C language projects
- Moderate size (easy to fuzz)
- High potential for fuzzing coverage
- Significant function pointer usage (callbacks, vtables, dispatch tables)

## Priority List (ranked by suitability):

### Tier 1: Excellent candidates (small, high function pointer usage, good fuzzing coverage)

1. **libexpat** - XML parser
   - Size: ~15K LOC
   - Function pointers: Handler callbacks for XML events (start/end element, character data, etc.)
   - Fuzzing: OSS-Fuzz project, excellent coverage
   - Source: https://github.com/libexpat/libexpat

2. **yajl** - Yet Another JSON Library
   - Size: ~5K LOC
   - Function pointers: Callback-based parsing API
   - Fuzzing: Well-suited for structured input fuzzing
   - Source: https://github.com/lloyd/yajl

3. **libxml2** - XML C parser
   - Size: ~100K LOC (moderate)
   - Function pointers: SAX handlers, XPath callbacks
   - Fuzzing: OSS-Fuzz project, extensive coverage
   - Source: https://gitlab.gnome.org/GNOME/libxml2

4. **libyaml** - YAML parser
   - Size: ~10K LOC
   - Function pointers: Event handlers
   - Fuzzing: Good for structured input
   - Source: https://github.com/yaml/libyaml

5. **bzip2** - Compression library
   - Size: ~8K LOC
   - Function pointers: I/O callbacks
   - Fuzzing: OSS-Fuzz project, good coverage
   - Source: https://sourceware.org/bzip2/

6. **zlib** - Compression library
   - Size: ~15K LOC
   - Function pointers: Memory allocation callbacks
   - Fuzzing: Well-fuzzed, stable
   - Source: https://github.com/madler/zlib

7. **mupdf** - PDF viewer/parser
   - Size: Moderate
   - Function pointers: Device callbacks, font handlers
   - Fuzzing: OSS-Fuzz project
   - Source: https://mupdf.com/

8. **libpng** - PNG library
   - Size: ~50K LOC
   - Function pointers: Error/warning handlers, I/O callbacks
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/glennrp/libpng

9. **libjpeg-turbo** - JPEG library
   - Size: ~50K LOC
   - Function pointers: Error managers, source/dest managers
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/libjpeg-turbo/libjpeg-turbo

10. **lz4** - Fast compression
    - Size: ~10K LOC
    - Function pointers: Memory handlers
    - Fuzzing: Simple API, good coverage
    - Source: https://github.com/lz4/lz4

### Tier 2: Good candidates (moderate complexity)

11. **zstd** - Fast compression
    - Size: ~50K LOC
    - Function pointers: Custom allocators, sequence producers
    - Fuzzing: OSS-Fuzz project
    - Source: https://github.com/facebook/zstd

12. **pcre2** - Regular expressions
    - Size: ~80K LOC
    - Function pointers: Match callbacks
    - Fuzzing: Good for pattern matching
    - Source: https://github.com/PCRE2Project/pcre2

13. **lua** - Scripting language
    - Size: ~20K LOC
    - Function pointers: C API callbacks, metamethods
    - Fuzzing: OSS-Fuzz project
    - Source: https://www.lua.org/

14. **mujs** - JavaScript interpreter
    - Size: ~20K LOC
    - Function pointers: Built-in functions, property handlers
    - Fuzzing: Good for JS parsing
    - Source: https://mujs.com/

15. **duktape** - Embeddable JavaScript
    - Size: ~80K LOC
    - Function pointers: Native functions, finalizers
    - Fuzzing: Good coverage potential
    - Source: https://duktape.org/

16. **mruby** - Lightweight Ruby
    - Size: Moderate
    - Function pointers: Method dispatch
    - Fuzzing: OSS-Fuzz project
    - Source: https://mruby.org/

17. **jansson** - JSON library
    - Size: ~8K LOC
    - Function pointers: Memory callbacks
    - Fuzzing: Simple structured input
    - Source: https://github.com/akheron/jansson

18. **cjson** - Ultra-lightweight JSON
    - Size: ~2K LOC
    - Function pointers: Memory hooks
    - Fuzzing: Very simple, good coverage
    - Source: https://github.com/DaveGamble/cJSON

19. **tomlc99** - TOML parser
    - Size: ~3K LOC
    - Function pointers: Minimal but present
    - Fuzzing: Simple structured format
    - Source: https://github.com/cktan/tomlc99

20. **tinyexpr** - Math expression parser
    - Size: ~1K LOC
    - Function pointers: Custom function callbacks
    - Fuzzing: Good for expression parsing
    - Source: https://github.com/codeplea/tinyexpr

## Recommendation:

**Top pick: libexpat**

Reasons:
1. Perfect size (~15K LOC) - not too big, not too small
2. Heavy function pointer usage - XML parser callbacks are a core design pattern
3. OSS-Fuzz project with proven good coverage
4. Well-maintained, stable API
5. CLI tool available (xmlwf) for easy fuzzing
6. Good dictionary and corpus available from OSS-Fuzz

EOF

# Candidate C Projects for Fuzzing (Not in current repo)

## Selection Criteria:
- C language projects
- Moderate size (easy to fuzz)
- High potential for fuzzing coverage
- Significant function pointer usage (callbacks, vtables, dispatch tables)

## Priority List (ranked by suitability):

### Tier 1: Excellent candidates (small, high function pointer usage, good fuzzing coverage)

1. **libexpat** - XML parser
   - Size: ~15K LOC
   - Function pointers: Handler callbacks for XML events (start/end element, character data, etc.)
   - Fuzzing: OSS-Fuzz project, excellent coverage
   - Source: https://github.com/libexpat/libexpat

2. **yajl** - Yet Another JSON Library
   - Size: ~5K LOC
   - Function pointers: Callback-based parsing API
   - Fuzzing: Well-suited for structured input fuzzing
   - Source: https://github.com/lloyd/yajl

3. **libxml2** - XML C parser
   - Size: ~100K LOC (moderate)
   - Function pointers: SAX handlers, XPath callbacks
   - Fuzzing: OSS-Fuzz project, extensive coverage
   - Source: https://gitlab.gnome.org/GNOME/libxml2

4. **libyaml** - YAML parser
   - Size: ~10K LOC
   - Function pointers: Event handlers
   - Fuzzing: Good for structured input
   - Source: https://github.com/yaml/libyaml

5. **bzip2** - Compression library
   - Size: ~8K LOC
   - Function pointers: I/O callbacks
   - Fuzzing: OSS-Fuzz project, good coverage
   - Source: https://sourceware.org/bzip2/

6. **zlib** - Compression library
   - Size: ~15K LOC
   - Function pointers: Memory allocation callbacks
   - Fuzzing: Well-fuzzed, stable
   - Source: https://github.com/madler/zlib

7. **mupdf** - PDF viewer/parser
   - Size: Moderate
   - Function pointers: Device callbacks, font handlers
   - Fuzzing: OSS-Fuzz project
   - Source: https://mupdf.com/

8. **libpng** - PNG library
   - Size: ~50K LOC
   - Function pointers: Error/warning handlers, I/O callbacks
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/glennrp/libpng

9. **libjpeg-turbo** - JPEG library
   - Size: ~50K LOC
   - Function pointers: Error managers, source/dest managers
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/libjpeg-turbo/libjpeg-turbo

10. **lz4** - Fast compression
    - Size: ~10K LOC
    - Function pointers: Memory handlers
    - Fuzzing: Simple API, good coverage
    - Source: https://github.com/lz4/lz4

### Tier 2: Good candidates (moderate complexity)

11. **zstd** - Fast compression
    - Size: ~50K LOC
    - Function pointers: Custom allocators, sequence producers
    - Fuzzing: OSS-Fuzz project
    - Source: https://github.com/facebook/zstd

12. **pcre2** - Regular expressions
    - Size: ~80K LOC
    - Function pointers: Match callbacks
    - Fuzzing: Good for pattern matching
    - Source: https://github.com/PCRE2Project/pcre2

13. **lua** - Scripting language
    - Size: ~20K LOC
    - Function pointers: C API callbacks, metamethods
    - Fuzzing: OSS-Fuzz project
    - Source: https://www.lua.org/

14. **mujs** - JavaScript interpreter
    - Size: ~20K LOC
    - Function pointers: Built-in functions, property handlers
    - Fuzzing: Good for JS parsing
    - Source: https://mujs.com/

15. **duktape** - Embeddable JavaScript
    - Size: ~80K LOC
    - Function pointers: Native functions, finalizers
    - Fuzzing: Good coverage potential
    - Source: https://duktape.org/

16. **mruby** - Lightweight Ruby
    - Size: Moderate
    - Function pointers: Method dispatch
    - Fuzzing: OSS-Fuzz project
    - Source: https://mruby.org/

17. **jansson** - JSON library
    - Size: ~8K LOC
    - Function pointers: Memory callbacks
    - Fuzzing: Simple structured input
    - Source: https://github.com/akheron/jansson

18. **cjson** - Ultra-lightweight JSON
    - Size: ~2K LOC
    - Function pointers: Memory hooks
    - Fuzzing: Very simple, good coverage
    - Source: https://github.com/DaveGamble/cJSON

19. **tomlc99** - TOML parser
    - Size: ~3K LOC
    - Function pointers: Minimal but present
    - Fuzzing: Simple structured format
    - Source: https://github.com/cktan/tomlc99

20. **tinyexpr** - Math expression parser
    - Size: ~1K LOC
    - Function pointers: Custom function callbacks
    - Fuzzing: Good for expression parsing
    - Source: https://github.com/codeplea/tinyexpr

## Recommendation:

**Top pick: libexpat**

Reasons:
1. Perfect size (~15K LOC) - not too big, not too small
2. Heavy function pointer usage - XML parser callbacks are a core design pattern
3. OSS-Fuzz project with proven good coverage
4. Well-maintained, stable API
5. CLI tool available (xmlwf) for easy fuzzing
6. Good dictionary and corpus available from OSS-Fuzz
