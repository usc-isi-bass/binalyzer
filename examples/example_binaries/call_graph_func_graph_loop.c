#include <stdio.h>
#include <stdlib.h>

void f(unsigned int n1, unsigned int n2)
{
    int i = 0;
    printf("f1 n1: %u n2: %u\n", n1, n2);
    if (n1 == 0 || n2 == 0) {
        return;
    }
    for (i = 0; i < n1; i++) {
        f(n1 - 1, n2 - 1);
    }
}


int main(int argc, char *argv[])
{
    unsigned int n1, n2;
    if (argc < 2) {
    
        fprintf(stderr, "usage: %s n1, n2\n", argv[0]);
        return EXIT_FAILURE;
    }
    n1 = atoi(argv[1]);
    n2 = atoi(argv[2]);
    f(n1, n2);
    return EXIT_SUCCESS;
}
