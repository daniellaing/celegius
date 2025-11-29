#include <stdlib.h>

#define CELEGIUS_IMPL
#include "celegius.h"

int main(void) {

  Cmd cmd = {0};
  cmd_init(&cmd);

  cmd_append(&cmd, "cc");
  cmd_append(&cmd, "-Wall", "-Wextra");
  cmd_append(&cmd, "celegius.c");
  cmd_append(&cmd, "-o", "build");

  cmd_run_async(&cmd);
  cmd_free(&cmd);

  return EXIT_SUCCESS;
}
