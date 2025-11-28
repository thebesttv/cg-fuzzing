// re2c with conditions
/*!re2c
    re2c:define:YYCTYPE = char;
    re2c:yyfill:enable = 0;
    re2c:condprefix = "yyc_";
    re2c:condenumprefix = "yyc";

    <init> [a-z]+  :=> normal
    <init> [0-9]+  :=> number
    <normal> ";"   :=> init
    <number> ";"   :=> init
    <*> *          { return ERR; }
*/
