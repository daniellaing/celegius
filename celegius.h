#ifndef CELEGIUS_H__
#define CELEGIUS_H__

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define cel_shift_arr(arr, count) ((count)--, *(arr)++)

#ifndef CEL_DA_INIT_CAP
#define DA_INIT_CAP 128U // Initial dynamic array capacity
#endif                   // !CEL_DA_INIT_CAP

#define CEL_DA_DEFINE(name, type)                                              \
  typedef struct {                                                             \
    type *items;                                                               \
    size_t count;                                                              \
    size_t capacity;                                                           \
  } name

#define cel_da_init(da)                                                        \
  do {                                                                         \
    (da)->items = NULL;                                                        \
    (da)->count = 0;                                                           \
    (da)->capacity = 0;                                                        \
  } while (0)

#define cel_da_next_capacity__(curr)                                           \
  ((curr) ? (((curr) < DA_INIT_CAP * 4) ? ((curr) * 3 / 2) : (curr) << 1)      \
          : DA_INIT_CAP)

#define cel_da_append(da, item)                                                \
  do {                                                                         \
    if ((da)->count >= (da)->capacity) {                                       \
      (da)->capacity = cel_da_next_capacity__((da)->capacity);                 \
      void *ptr = realloc((da)->items, (da)->capacity * sizeof(*(da)->items)); \
      if (ptr == NULL) {                                                       \
        fprintf(stderr, "Could not extend dynamic array. Buy more RAM\n");     \
        exit(EXIT_FAILURE);                                                    \
      }                                                                        \
      (da)->items = ptr;                                                       \
    }                                                                          \
    (da)->items[(da)->count++] = item;                                         \
  } while (0)

#define cel_da_append_many(da, new_items, num)                                 \
  do {                                                                         \
    if ((da)->count + num > (da)->capacity) {                                  \
      (da)->capacity = (da)->count + num;                                      \
      void *ptr = realloc((da)->items, (da)->capacity * sizeof(*(da)->items)); \
      if (ptr == NULL) {                                                       \
        fprintf(stderr, "Could not extend dynamic array. Buy more RAM\n");     \
        exit(EXIT_FAILURE);                                                    \
      }                                                                        \
      (da)->items = ptr;                                                       \
    }                                                                          \
    memcpy((da)->items + (da)->count, new_items, num * sizeof(*(da)->items));  \
    (da)->count += num;                                                        \
  } while (0)

#define cel_da_foreach(type, item, da)                                         \
  for (type *item = (da)->items; item < (da)->items + (da)->count; item++)

#define cel_da_clear(da)                                                       \
  do {                                                                         \
    memset((da)->items, 0, (da)->count);                                       \
    (da)->count = 0;                                                           \
  } while (0)

#define cel_da_free(da)                                                        \
  do {                                                                         \
    free((da)->items);                                                         \
    (da)->items = NULL;                                                        \
    (da)->count = 0;                                                           \
    (da)->capacity = 0;                                                        \
  } while (0)

CEL_DA_DEFINE(String_Builder, char);

CEL_DA_DEFINE(Cmd, const char *);
#define cel_cmd_init cel_da_init
#define cel_cmd_clear cel_da_clear
#define cel_cmd_free cel_da_free
#define cel_cmd_append(cmd, ...)                                               \
  cel_da_append_many(cmd, ((const char *[]){__VA_ARGS__}),                     \
                     (sizeof((const char *[]){__VA_ARGS__})) /                 \
                         sizeof(const char *))
#define cel_cmd_append_many cel_da_append_many
#define cel_cmd_display(cmd, sb)                                               \
  do {                                                                         \
    cel_da_foreach(const char *, arg, cmd) {                                   \
      size_t len = strlen(*arg);                                               \
      cel_da_append_many(sb, *arg, len);                                       \
      cel_da_append(sb, ' ');                                                  \
    }                                                                          \
    (sb)->items[--((sb)->count)] = '\0';                                       \
  } while (0)

pid_t cel_cmd_run_async(Cmd *cmd);
bool cel_cmd_run_sync(Cmd *cmd);
bool cel_cmd_wait(pid_t pid);
int cel_needs_rebuild(const char *const bin_path, ...);

#define CEL_AUTO_REBUILD(argc, argv)                                           \
  do {                                                                         \
    const char *const binary_name = cel_shift_arr(argv, argc);                 \
    const char *const source_name = __FILE__;                                  \
                                                                               \
    int rebuild = cel_needs_rebuild(binary_name, source_name, NULL);           \
    if (rebuild < 0)                                                           \
      exit(EXIT_FAILURE);                                                      \
                                                                               \
    if (rebuild) {                                                             \
      fprintf(stderr, "[INFO] Rebuilding %s\n", binary_name);                  \
                                                                               \
      char old_bin_path[strlen(binary_name) + 5];                              \
      sprintf(old_bin_path, "%s.old", binary_name);                            \
      fprintf(stderr, "[INFO] Renaming %s -> %s\n", binary_name,               \
              old_bin_path);                                                   \
      rename(binary_name, old_bin_path);                                       \
                                                                               \
      Cmd rebuildcmd = {0};                                                    \
      cel_cmd_init(&rebuildcmd);                                               \
                                                                               \
      cel_cmd_append(&rebuildcmd, "cc", "-o", binary_name, source_name);       \
      if (!cel_cmd_run_sync(&rebuildcmd)) {                                    \
        fprintf(stderr, "[ERROR] Rebuild failed!\n");                          \
        fprintf(stderr, "[INFO] Renaming %s -> %s\n", old_bin_path,            \
                binary_name);                                                  \
        rename(old_bin_path, binary_name);                                     \
        exit(EXIT_FAILURE);                                                    \
      }                                                                        \
                                                                               \
      cel_cmd_clear(&rebuildcmd);                                              \
      cel_cmd_append(&rebuildcmd, binary_name);                                \
      cel_cmd_append_many(&rebuildcmd, argv, argc);                            \
      if (!cel_cmd_run_sync(&rebuildcmd))                                      \
        exit(EXIT_FAILURE);                                                    \
      exit(EXIT_SUCCESS);                                                      \
    }                                                                          \
  } while (0)

#endif // !CELEGIUS_H__

#define CELEGIUS_IMPL
#ifdef CELEGIUS_IMPL

pid_t cel_cmd_run_async(Cmd *cmd) {
  String_Builder sb = {0};
  cel_da_init(&sb);
  cel_cmd_display(cmd, &sb);
  fprintf(stderr, "[CMD] %s\n", sb.items);
  cel_da_free(&sb);

  pid_t child_pid = fork();
  if (child_pid < 0) {
    fprintf(stderr, "[ERROR] Could not fork process to execute command: %s\n",
            strerror(errno));
    return child_pid;
  }

  // If we have the child PID, then just return it.
  if (child_pid > 0) {
    return child_pid;
  }

  // Otherwise we are in the child process, so execute the command
  cel_cmd_append(cmd, NULL);
  if (execvp(cmd->items[0], (char *const *)cmd->items) < 0) {
    fprintf(stderr, "[ERROR] Could not execute command: %s\n", strerror(errno));
    return -1;
  }

  fprintf(stderr,
          "[ERROR] Unreachable: exec returned success. This is a bug.\n");
  exit(EXIT_FAILURE);
}

bool cel_cmd_run_sync(Cmd *cmd) {
  pid_t pid = cel_cmd_run_async(cmd);
  if (pid < 0)
    return false;
  return cel_cmd_wait(pid);
}

bool cel_cmd_wait(pid_t pid) {
  int status = 0;
  for (; /* ever */;) {
    if (waitpid(pid, &status, 0) < 0) {
      fprintf(stderr, "[ERROR] Could not wait on command: %s\n",
              strerror(errno));
      return false;
    }

    if (WIFEXITED(status)) {
      int exit_status = WEXITSTATUS(status);
      if (exit_status != 0) {
        fprintf(stderr, "[ERROR] Command exitied with code %d\n", exit_status);
        return false;
      }
      break;
    }

    if (WIFSIGNALED(status)) {
      fprintf(stderr, "[ERROR] Command was terminated by %s\n",
              strsignal(WTERMSIG(status)));
      return false;
    }
  }

  return true;
}

int cel_needs_rebuild(const char *const bin_path, ...) {
  struct stat statbuf = {0};

  if (stat(bin_path, &statbuf) < 0) {
    fprintf(stderr, "[ERROR] Could not get stats on file %s: %s\n", bin_path,
            strerror(errno));
    return -1;
  }
  const int binmtime = statbuf.st_mtime;

  va_list src_paths = {0};
  va_start(src_paths, bin_path);

  char *srcp;
  while ((srcp = va_arg(src_paths, char *)) != NULL) {
    if (stat(srcp, &statbuf) < 0) {
      fprintf(stderr, "[ERROR] Could not get stats on file %s: %s\n", srcp,
              strerror(errno));
      return -1;
    }
    if (statbuf.st_mtime > binmtime)
      return 1;
  }
  va_end(src_paths);
  return 0;
}

#endif // CELEGIUS_IMPL

#ifndef CEL_STRIP_PREFIX_H__
#define CEL_STRIP_PREFIX_H__

#ifdef CEL_STRIP_PREFIX

#define shift_arr cel_shift_arr
#define DA_DEFINE CEL_DA_DEFINE
#define da_init cel_da_init
#define da_next_capacity__ cel_da_next_capacity__
#define da_append cel_da_append
#define da_append_many cel_da_append_many
#define da_foreach cel_da_foreach
#define da_clear cel_da_clear
#define da_free cel_da_free
#define cmd_init cel_cmd_init
#define cmd_clear cel_cmd_clear
#define cmd_free cel_cmd_free
#define cmd_append cel_cmd_append
#define cmd_append_many cel_cmd_append_many
#define cmd_display cel_cmd_display
#define cmd_run_async cel_cmd_run_async
#define cmd_run_sync cel_cmd_run_sync
#define cmd_wait cel_cmd_wait
#define needs_rebuild cel_needs_rebuild
#define AUTO_REBUILD CEL_AUTO_REBUILD

#endif // CEL_STRIP_PREFIX

#endif // !CEL_STRIP_PREFIX_H__
