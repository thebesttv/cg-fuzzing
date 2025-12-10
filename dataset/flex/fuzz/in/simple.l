%{
#include <stdio.h>
%}

%%
[0-9]+          { printf("NUMBER: %s\n", yytext); }
[a-zA-Z_]+      { printf("ID: %s\n", yytext); }
[ \t\n]+        ;
.               { printf("UNKNOWN: %s\n", yytext); }
%%

int yywrap() { return 1; }
