# Candidate C Projects for Fuzzing (Not in current repo)

## Selection Criteria:
- C language projects
- Moderate size (easy to fuzz)
- High potential for fuzzing coverage
- Significant function pointer usage (callbacks, vtables, dispatch tables)

## Already Completed:
- **jq** - JSON processor (in repo)
- **sqlite** - Database engine (in repo)
- **coreutils** - GNU core utilities (in repo, bc only)
- **libexpat** - XML parser (in repo)
- **yajl** - Yet Another JSON Library (in repo)
- **libyaml** - YAML parser (in repo)
- **bzip2** - Compression library (in repo)
- **lz4** - Fast compression (in repo)
- **zlib** - Compression library (in repo)
- **libpng** - PNG library (in repo)
- **pcre2** - Regular expressions (in repo)
- **jansson** - JSON library (in repo)
- **cjson** - Ultra-lightweight JSON (in repo)
- **tomlc99** - TOML parser (in repo)
- **duktape** - Embeddable JavaScript v2.7.0 (in repo)
- **mruby** - Lightweight Ruby v3.4.0 (in repo)
- **inih** - INI parser r62 (in repo)
- **re2c** - Lexer generator v4.3 (in repo)

## Priority List (ranked by suitability):

### Tier 1: Excellent candidates (small, high function pointer usage, good fuzzing coverage)

1. **libxml2** - XML C parser
   - Size: ~100K LOC (moderate)
   - Function pointers: SAX handlers, XPath callbacks
   - Fuzzing: OSS-Fuzz project, extensive coverage
   - Source: https://gitlab.gnome.org/GNOME/libxml2

2. **zlib** - Compression library
   - Size: ~15K LOC
   - Function pointers: Memory allocation callbacks
   - Fuzzing: Well-fuzzed, stable
   - Source: https://github.com/madler/zlib

3. **mupdf** - PDF viewer/parser
   - Size: Moderate
   - Function pointers: Device callbacks, font handlers
   - Fuzzing: OSS-Fuzz project
   - Source: https://mupdf.com/

4. **libpng** - PNG library
   - Size: ~50K LOC
   - Function pointers: Error/warning handlers, I/O callbacks
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/glennrp/libpng

5. **libjpeg-turbo** - JPEG library
   - Size: ~50K LOC
   - Function pointers: Error managers, source/dest managers
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/libjpeg-turbo/libjpeg-turbo

### Tier 2: Good candidates (moderate complexity)

6. **zstd** - Fast compression
   - Size: ~50K LOC
   - Function pointers: Custom allocators, sequence producers
   - Fuzzing: OSS-Fuzz project
   - Source: https://github.com/facebook/zstd

7. **pcre2** - Regular expressions
    - Size: ~80K LOC
    - Function pointers: Match callbacks
    - Fuzzing: Good for pattern matching
    - Source: https://github.com/PCRE2Project/pcre2

8. **lua** - Scripting language
    - Size: ~20K LOC
    - Function pointers: C API callbacks, metamethods
    - Fuzzing: OSS-Fuzz project
    - Source: https://www.lua.org/

9. **mujs** - JavaScript interpreter
    - Size: ~20K LOC
    - Function pointers: Built-in functions, property handlers
    - Fuzzing: Good for JS parsing
    - Source: https://mujs.com/

10. **duktape** - Embeddable JavaScript
    - Size: ~80K LOC
    - Function pointers: Native functions, finalizers
    - Fuzzing: Good coverage potential
    - Source: https://duktape.org/

11. **mruby** - Lightweight Ruby
    - Size: Moderate
    - Function pointers: Method dispatch
    - Fuzzing: OSS-Fuzz project
    - Source: https://mruby.org/

12. **jansson** - JSON library
    - Size: ~8K LOC
    - Function pointers: Memory callbacks
    - Fuzzing: Simple structured input
    - Source: https://github.com/akheron/jansson

13. **cjson** - Ultra-lightweight JSON
    - Size: ~2K LOC
    - Function pointers: Memory hooks
    - Fuzzing: Very simple, good coverage
    - Source: https://github.com/DaveGamble/cJSON

14. **tomlc99** - TOML parser
    - Size: ~3K LOC
    - Function pointers: Minimal but present
    - Fuzzing: Simple structured format
    - Source: https://github.com/cktan/tomlc99

15. **tinyexpr** - Math expression parser
    - Size: ~1K LOC
    - Function pointers: Custom function callbacks
    - Fuzzing: Good for expression parsing
    - Source: https://github.com/codeplea/tinyexpr

## Recommendation:

**Top pick: libxml2**

Reasons:
1. Moderate size (~100K LOC) - comprehensive XML support
2. Heavy function pointer usage - SAX handlers, XPath callbacks are core design patterns
3. OSS-Fuzz project with proven extensive coverage
4. Well-maintained, widely used library
5. CLI tool available (xmllint) for easy fuzzing
6. Good dictionary and corpus available from OSS-Fuzz
