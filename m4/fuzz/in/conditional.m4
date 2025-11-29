dnl Example with conditionals
define(`MY_VAR', `100')
ifdef(`MY_VAR', `MY_VAR is defined', `MY_VAR is not defined')
ifelse(MY_VAR, `100', `It is 100', `It is not 100')
