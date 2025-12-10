#include <stdlib.h>
#define SIZE 1024
#if SIZE > 512
#define BUF_SIZE SIZE*2
#elif SIZE > 256
#define BUF_SIZE SIZE
#else
#define BUF_SIZE 256
#endif
