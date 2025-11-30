%token A B C

%start start

%%

start: list
     ;

list: /* empty */
    | list item
    ;

item: A
    | B  
    | C
    | error
    ;

%%
