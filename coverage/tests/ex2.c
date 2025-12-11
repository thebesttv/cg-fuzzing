#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    int n;
    scanf("%d", &n);

    int x, y;
    for (int i = 0; i < n; ++i)
    {
        scanf("%d%d", &x, &y);

        if (x > 10 && y < 20)
        {
            printf("condition met: x=%d y=%d\n", x, y);
        }
        else
        {
            printf("condition not met: x=%d y=%d\n", x, y);
        }
    }

    return 0;
}
