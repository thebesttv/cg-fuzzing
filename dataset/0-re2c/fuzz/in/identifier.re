// re2c identifier scanner
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;

    id = [a-zA-Z_][a-zA-Z_0-9]*;
    ws = [ \t\n\r]+;

    ws   { goto yyc_scan; }
    id   { return ID; }
    *    { return ERR; }
*/
