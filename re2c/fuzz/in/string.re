// re2c string scanner with escape sequences
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;

    esc = "\\" [nrt\\"];
    str = "\"" (esc | [^"\\])* "\"";

    str  { return STRING; }
    *    { return ERR; }
*/
