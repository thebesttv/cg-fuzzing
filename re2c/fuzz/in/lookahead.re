// re2c with lookahead
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;

    kw   = "if" | "else" | "while" | "for";
    id   = [a-zA-Z_][a-zA-Z_0-9]*;

    kw / [^a-zA-Z_0-9] { return KEYWORD; }
    id                 { return ID; }
    *                  { return ERR; }
*/
