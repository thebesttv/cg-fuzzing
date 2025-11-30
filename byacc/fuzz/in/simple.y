%{
#include <stdio.h>
%}

%token NUM

%%

expr: NUM
    ;

%%
