%{
#include <stdio.h>
int yylex(void);
void yyerror(const char *s);
%}

%union {
    int ival;
    char *sval;
}

%token <ival> NUMBER
%token <sval> STRING
%token ID

%left '+' '-'
%left '*' '/'
%right UMINUS

%type <ival> expr

%%
program: stmts
       ;

stmts: stmts stmt
     | stmt
     ;

stmt: expr '\n'     { printf("= %d\n", $1); }
    | '\n'
    ;

expr: NUMBER        { $$ = $1; }
    | expr '+' expr { $$ = $1 + $3; }
    | expr '-' expr { $$ = $1 - $3; }
    | expr '*' expr { $$ = $1 * $3; }
    | expr '/' expr { $$ = $1 / $3; }
    | '-' expr %prec UMINUS { $$ = -$2; }
    | '(' expr ')'  { $$ = $2; }
    ;
%%

void yyerror(const char *s) {
    fprintf(stderr, "error: %s\n", s);
}
