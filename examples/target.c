#include <stdio.h>
#include <fcntl.h>

int main() {

    char input[100];

    FILE * f = fopen('./testcase', O_RDONLY);
    char *s = input;

    while (*s != EOF) {
        *s = fgetc(f);
        s++;
    }

    printf("%s\n", input);

}
