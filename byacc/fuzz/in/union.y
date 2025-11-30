%{
typedef struct { int val; } YYSTYPE;
%}

%union {
    int intval;
    char *strval;
}

%token <intval> INTEGER
%token <strval> STRING
%type <intval> expr

%%

program: /* empty */
       | program statement
       ;

statement: expr ';'
         ;

expr: INTEGER
    | expr '+' expr { $$ = $1 + $3; }
    ;

%%
