// re2c with submatch extraction (tags)
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;
    re2c:flags:T = 1;

    date = @y [0-9]{4} "-" @m [0-9]{2} "-" @d [0-9]{2};

    date { return DATE; }
    *    { return ERR; }
*/
