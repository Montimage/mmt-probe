/*
 * dbl_list.h
 */

#ifndef SRC_LIB_DBL_LIST_H_
#define SRC_LIB_DBL_LIST_H_

#include <stdio.h>

/**
 * Double linked list structure
 */
struct list_entry {
	struct list_entry *next, *prev;
};

/**
 * List node initialization
 */
static inline void init_list_head(struct list_entry *list) {
	list->next = list;
	list->prev = list;
}

/**
 * Test if list is empty
 */
static inline int list_empty(struct list_entry *list) {
	return (list->next == list);
}

/**
 * Add a node at list tail
 */
static inline void list_add_tail(struct list_entry *new,
		struct list_entry *head) {
	new->next = head;
	head->prev->next = new;
	new->prev = head->prev;
	head->prev = new;
}

/**
 * Remove a node from list
 */
static inline void list_del(struct list_entry *entry) {
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
	entry->next = NULL;
	entry->prev = NULL;
}

#endif /* SRC_LIB_DBL_LIST_H_ */
