
#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int x, y;
    scanf("%d %d", &x, &y);

    if (x && y)
    {
        printf("both non-zero: x=%d y=%d\n", x, y);
    }
    else
    {
        printf("not both non-zero: x=%d y=%d\n", x, y);
    }

    return 0;
}
