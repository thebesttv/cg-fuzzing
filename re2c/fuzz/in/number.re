// re2c number scanner
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;

    dec = [1-9][0-9]*;
    oct = "0" [0-7]*;
    hex = "0" [xX] [0-9a-fA-F]+;
    flt = [0-9]+ "." [0-9]* ([eE] [+-]? [0-9]+)?;

    dec  { return DEC; }
    oct  { return OCT; }
    hex  { return HEX; }
    flt  { return FLT; }
    *    { return ERR; }
*/
