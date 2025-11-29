#include <stdio.h>
#include <stdlib.h>

#define CELEGIUS_IMPL
#define CEL_STRIP_PREFIX
#include "celegius.h"

int main(int argc, char **argv) {
  printf("Args: ");
  for (int i = 1; i < argc; i++) {
    printf("%s ", argv[i]);
  }
  printf("\n");

  AUTO_REBUILD(argc, argv);

  printf("---------------------\n");

  // Build
  Cmd cmd = {0};
  cmd_init(&cmd);

  cmd_append(&cmd, "cc");
  cmd_append(&cmd, "-Wall", "-Wextra");
  cmd_append(&cmd, "celegius.c");
  cmd_append(&cmd, "-o", "build");

  cmd_run_sync(&cmd);
  cmd_free(&cmd);

  return EXIT_SUCCESS;
}
