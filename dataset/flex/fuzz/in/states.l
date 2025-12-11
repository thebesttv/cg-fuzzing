%option noyywrap
%option yylineno

%x COMMENT

%%
"/*"            { BEGIN(COMMENT); }
<COMMENT>"*/"   { BEGIN(INITIAL); }
<COMMENT>.      ;
<COMMENT>\n     ;

"//".*          ;

[0-9]+\.[0-9]+  { printf("FLOAT\n"); }
[0-9]+          { printf("INT\n"); }
\"[^"]*\"       { printf("STRING\n"); }
[ \t\n]+        ;
.               ;
%%
