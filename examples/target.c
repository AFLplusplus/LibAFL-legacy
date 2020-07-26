#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

char file_name[20] = "./testcase";

int main() {

  char input[100] = {'\x00'};

  int r = read(0, input, 50);

  int fd = open("./success", O_RDWR | O_CREAT, 0600);

  write(fd, input, 50);

  exit(0);

}

