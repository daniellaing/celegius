#ifndef CELEGIUS_H__
#define CELEGIUS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DA_INIT_CAP 128U // Initial dynamic array capacity

#define DA_DEFINE(name, type)                                                  \
  typedef struct {                                                             \
    type *items;                                                               \
    size_t count;                                                              \
    size_t capacity;                                                           \
  } name

#define da_init(da)                                                            \
  do {                                                                         \
    (da)->items = NULL;                                                        \
    (da)->count = 0;                                                           \
    (da)->capacity = 0;                                                        \
  } while (0)

#define da_next_capacity__(curr)                                               \
  ((curr) ? (((curr) < DA_INIT_CAP * 4) ? ((curr) * 3 / 2) : (curr) << 1)      \
          : DA_INIT_CAP)

#define da_append(da, item)                                                    \
  do {                                                                         \
    if ((da)->count >= (da)->capacity) {                                       \
      (da)->capacity = da_next_capacity__((da)->capacity);                     \
      void *ptr = realloc((da)->items, (da)->capacity * sizeof(*(da)->items)); \
      if (ptr == NULL) {                                                       \
        fprintf(stderr, "Could not extend dynamic array. Buy more RAM\n");     \
        exit(EXIT_FAILURE);                                                    \
      }                                                                        \
      (da)->items = ptr;                                                       \
    }                                                                          \
    (da)->items[(da)->count++] = (item);                                       \
  } while (0)

#define da_append_many(da, new_items, num)                                     \
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

#define da_free(da)                                                            \
  do {                                                                         \
    free((da)->items);                                                         \
    (da)->items = NULL;                                                        \
    (da)->count = 0;                                                           \
    (da)->capacity = 0;                                                        \
  } while (0)

DA_DEFINE(Cmd, const char *);
#define cmd_init da_init
#define cmd_free da_free
#define cmd_append(cmd, ...)                                                   \
  da_append_many(cmd, ((const char *[]){__VA_ARGS__}),                         \
                 (sizeof((const char *[]){__VA_ARGS__})) /                     \
                     sizeof(const char *))

#endif // !CELEGIUS_H__

#define CELEGIUS_IMPL
#ifdef CELEGIUS_IMPL

#endif // CELEGIUS_IMPL
