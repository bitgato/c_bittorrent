#ifndef LIST_H
#define LIST_H

#include "bencode.h"

/**
 * Creates a list of bencoded nodes
 * @param node Initial node
 */
be_list *list_create (be_node node);

/**
 * Adds a bencoded node to a list
 * @param list The list to which the node is to be added
 * @param node The node to be added
 */
be_list *list_add (be_list *list, be_node node);

/**
 * Frees a list of bencoded nodes. Generally. no need to use this as
 * callign dict_destroy() will free the lists in a dictionary anyways
 * @param list The list to be freed
 * @see dict_destroy
 */
void list_free (be_list *list);

#endif /* LIST_H */