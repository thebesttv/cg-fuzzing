#include <stdio.h>
#define MAX 100
#ifdef DEBUG
#define LOG(x) printf("%s\n", x)
#else
#define LOG(x)
#endif
int main() {
    return 0;
}
