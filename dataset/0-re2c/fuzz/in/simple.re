// Simple re2c example - integer scanner
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;

    [0-9]+ { return 1; }
    *      { return 0; }
*/
