#include <stdio.h>
#include <stdlib.h>

int divide(int x, int y)
{

    return x / y;
}

int main(int argc, char *argv[])
{
    int x, y;
    int q;
    if (argc < 3) {
        printf("%s x y\n", argv[0]);
        return EXIT_SUCCESS;
    }
    argv[1] = '\0';
    argv[2] = '\0';
    x = atoi(argv[1]);
    y = atoi(argv[2]);
    q = divide(x, y);

    printf("%d / %d = %d\n", x, y, q);
    

    return EXIT_SUCCESS;
}
