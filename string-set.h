#ifndef _STRING_SET_H
#define _STRING_SET_H

struct str_set {
  int length;
  int size;
  struct member {
    struct member *link;
    const char *element;
  } **buckets;
};

struct str_set *str_set_new();
void str_set_put(struct str_set *set, const char *elem);
char *str_set_remove(struct str_set *set, const char *elem);
int str_set_length(struct str_set *set);
int is_str_set_member(struct str_set *set, const void *elem);
void str_set_free(struct str_set **set);

#endif
