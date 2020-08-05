#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

char file_name[20] = "./testcase";

int main() {

  char input[100] = {'\x00'};

  int r = read(0, input, 50);
  if (!r) { puts("Error!\n"); }

  if (input[2] == 'B' || input[2] == 'C') {

    puts("1st block hit");
    //int x = 1;

    if (input[2] == 'C') {

      puts("2nd block hit");
      //int y = 2;

    }

  }

  int fd = open("./success", O_RDWR | O_CREAT, 0600);

  write(fd, input, 50);

  exit(0);

}

