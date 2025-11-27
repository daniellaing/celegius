#include <stdio.h>
#include <stdlib.h>

#define CELAGIUS_IMPL
#include "celegius.h"

int main(void) {

  Cmd cmd = {0};
  cmd_init(&cmd);

  cmd_append(&cmd, "cc");
  cmd_append(&cmd, "-Wall"
                   "-Wextra");
  cmd_append(&cmd, "celegius.c");
  cmd_append(&cmd, "-o", "build");

  for (size_t i = 0; i < cmd.count; i++) {
    printf("%s ", cmd.items[i]);
  }
  printf("\n");

  cmd_free(&cmd);

  return EXIT_SUCCESS;
}
