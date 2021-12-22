#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>

#include "bencode.h"
#include "list.h"

static uint32_t
hash_key(unsigned char *key)
{
	uint32_t hash = FNV_OFF;
	for(unsigned char* p = key; *p; ++p) {
		hash ^= (uint32_t)(*p);
		hash *= hash*FNV_PRIME;
	}
	return hash;
}

be_dict*
dict_create()
{
	be_dict *dict = malloc(sizeof(be_dict));
	if(dict == NULL) return dict;
	dict->length = 0;
	dict->has_info_hash = false;
	// Initialize all elements in info hash to 0
	memset(dict->info_hash, 0, SHA_DIGEST_LENGTH);
	dict->capacity = INIT_CAP;

	dict->entries = calloc(dict->capacity, sizeof(be_node));
	if(dict->entries == NULL) {
		free(dict);
		return NULL;
	}

	return dict;
}

static void
node_free(be_node node)
{
	if(node.val==NULL) return;
	switch(node.type) {
		case BE_INT: break; // Don't need to free integers
		case BE_STR: {
			be_string *string = node.val;
			free(string->str);
			free(string);
			break;
		}
		case BE_LIST: {
			list_free(node.val);
			break;
		}
		case BE_DICT: {
			dict_destroy((be_dict*)node.val);
			break;
		}
	}
}

be_list*
list_create(be_node node)
{
	be_list *list = malloc(sizeof(be_list));
	if(list!=NULL) {
		list->node = node;
		list->last = list;
		list->next = NULL;
	}
	return list;
}

be_list*
list_add(be_list *list, be_node node)
{
	be_list *new_node = list_create(node);
	if(new_node==NULL) {
		list_free(list);
		list = NULL;
		return list;
	}
	list->last->next = new_node;
	list->last = new_node;
	return list;
}

void
list_free(be_list *list)
{
	if(list==NULL) return;
	node_free(list->node);
	list_free(list->next);
	free(list);
}

void
dict_destroy(be_dict *dict)
{
	if(dict==NULL) return;
	for(size_t i=0; i<dict->capacity; ++i) {
		if(dict->entries[i].key != NULL) {
			free(dict->entries[i].key);
			node_free(dict->entries[i]);
		}
	}
	free(dict->entries);
	free(dict);
}

static unsigned char*
dict_set_entry(be_node *entries, size_t capacity, unsigned char *key,
	void *val, size_t *length, be_type type)
{
	uint32_t hash = hash_key(key);
	size_t index = (size_t)(hash & (uint32_t)(capacity-1));

	while(entries[index].key!=NULL) {
		if(strcmp((char*)key, (char*)entries[index].key)==0) {
			entries[index].val = val;
			return entries[index].key;
		}
		++index;
		if(index>=capacity) index = 0;
	}

	entries[index].key = key;
	entries[index].val = val;
	entries[index].type = type;
	++(*length);
	return key;
}

static bool
dict_expand(be_dict *dict)
{
	size_t new_cap = dict->capacity*2;
	if(new_cap < dict->capacity) return false; // Overflow
	be_node *new_entries = calloc(new_cap, sizeof(be_node));
	if(new_entries == NULL) return false;

	for(size_t i=0; i<dict->capacity; ++i) {
		be_node entry = dict->entries[i];
		if(entry.key!=NULL) {
			dict_set_entry(new_entries, new_cap, entry.key, entry.val,
				NULL, entry.type);
		}
	}

	free(dict->entries);
	dict->entries = new_entries;
	dict->capacity = new_cap;
	return true;
}

void*
dict_get(be_dict *dict, unsigned char *key, be_type *type)
{
	uint32_t hash = hash_key(key);
	size_t index = (size_t)(hash & (uint32_t)(dict->capacity-1));

	while(dict->entries[index].key!=NULL) {
		if(strcmp((char*)key, (char*)dict->entries[index].key)==0) {
			*type = dict->entries[index].type;
			return dict->entries[index].val;
		}
		++index;
		if(index>=dict->capacity) index = 0;
	}

	return NULL;
}

unsigned char*
dict_set(be_dict *dict, unsigned char *key, void *val, be_type type)
{
	if(val == NULL && type!=BE_INT) {
		return NULL;
	}
	if(dict->length >= dict->capacity-1) {
		if(!dict_expand(dict)) return NULL;
	}
	return dict_set_entry(dict->entries, dict->capacity, key, val,
		&dict->length, type);
}

void
dict_dump(be_dict *dict)
{
	struct be_node *entries = dict->entries;
	for(size_t i=0; i<dict->capacity; ++i) {
		if(entries[i].key!=NULL) {
			dict_val_print(entries[i].key, entries[i].val, entries[i].type);
		}
	}
}
