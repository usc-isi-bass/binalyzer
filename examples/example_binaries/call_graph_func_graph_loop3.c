#include <stdio.h>
#include <stdlib.h>

void f1(unsigned int n);
void f2(unsigned int n);

void f1(unsigned int n)
{
    unsigned int i;
    if (n == 0) {
        return;
    }
    printf("f1 n: %u\n", n);
    for (i = 0; i < n; i++) {
        printf("f1 i: %u n: %u\n", i, n);
        f2(n - 1);
    }
}

void f2(unsigned int n)
{
    unsigned int i;
    for (i = 0; i < n; i++) {
        printf("f2 i: %u n: %u\n", i, n);
        f1(n);
    }
}

int main(int argc, char *argv[])
{
    unsigned int n;
    if (argc < 2) {
    
        fprintf(stderr, "usage: %s n\n", argv[0]);
        return EXIT_FAILURE;
    }
    n = atoi(argv[1]);
    f1(n);
    return EXIT_SUCCESS;
}

