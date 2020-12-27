#include <stdio.h>
#include <stdlib.h>

void f(unsigned int n)
{
    if (n == 0) {
        return;
    }
    printf("n: %u\n", n);
    f(n - 1);
}

int main(int argc, char *argv[])
{
    unsigned int n;
    if (argc < 2) {
    
        fprintf(stderr, "usage: %s n\n", argv[0]);
        return EXIT_FAILURE;
    }
    n = atoi(argv[1]);
    f(n);
    return EXIT_SUCCESS;
}
