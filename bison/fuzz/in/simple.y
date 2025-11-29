%{
#include <stdio.h>
void yyerror(const char *s);
int yylex(void);
%}

%token NUM

%%
expr: NUM
    | expr '+' expr
    | '(' expr ')'
    ;
%%

void yyerror(const char *s) {
    fprintf(stderr, "%s\n", s);
}
