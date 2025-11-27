#include <stdio.h>
#include <stdlib.h>

#define CELAGIUS_IMPL
#include "celegius.h"

DA_DEFINE(String_Builder, char);

int main(void) {

  String_Builder sb = {0};
  da_init(&sb);

  da_append(&sb, 'H');
  da_append_many(&sb, "ello World", 10);

  printf("%s\n", sb.items);
  da_free(&sb);

  return EXIT_SUCCESS;
}
