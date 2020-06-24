#include <stdio.h>
#include <fcntl.h>

char file_name[20] = "./testcase";

int main() {

  char input[100];

  char * fname = file_name;

  FILE *f = fopen(fname, "r+");
  char *s = input;

  while (*s != EOF) {

    *s = fgetc(f);
    s++;

  }

  int fd = open('./output', O_RDWR | O_CREAT);

  write(fd, "SUCCESS!!\x00\x00");

  printf("%s\n", input);

}

