.if defined(DEBUG)
CFLAGS = -g
.else
CFLAGS = -O2
.endif
all:
echo $(CFLAGS)
