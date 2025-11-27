#include <stdio.h>
#include <stdlib.h>

#define CELAGIUS_IMPL
#include "celegius.h"

int main(void) {

  Cmd cmd = {0};
  cmd_init(&cmd);

  cmd_append(&cmd, "cc");
  cmd_append(&cmd, "-v");
  cmd_append(&cmd, "-Wall", "-Wextra");
  cmd_append(&cmd, "celegius.c");
  cmd_append(&cmd, "-o", "build");

  String_Builder sb = {0};
  da_init(&sb);
  cmd_display(&cmd, &sb);
  printf("%s", sb.items);

  da_free(&sb);
  cmd_free(&cmd);

  return EXIT_SUCCESS;
}
