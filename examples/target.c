#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

char file_name[20] = "./testcase";

int main() {

  char input[100] = {'\x00'};

  int r = read(0, input, 50);
  if (!r) { puts("Error!\n"); }

  printf("In target\n");

  if (input[2] == 'B' || input[2] == 'C') {

    puts("1st block hit");

    if (input[2] == 'C') {

      puts("2nd block hit");
      *(volatile int *)(NULL) = 0x0;  // Crash

    }

  }

  exit(0);

}

