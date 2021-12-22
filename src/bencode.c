#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "bencode.h"
#include "list.h"

static be_string*
decode_str(unsigned char **buffer, size_t *buff_len)
{
	be_string *string = NULL;
	char *endp;
	unsigned char *str = NULL;
	size_t len = 0;

	len = strtol((char*)*buffer, &endp, 10);

	if(*endp!=':') return string; // If the integer isn't followed by a colon
	*buff_len -= (endp - (char*)*buffer);
	*buffer = (unsigned char*)endp;
	--(*buff_len); ++(*buffer); // Consume ':'

	// If we don't have enough buffer left
	if(len>*buff_len-1) return string;

	string = malloc(sizeof(be_string));
	if(string==NULL) return NULL;
	str = malloc(len+1);
	if(str==NULL) {
		free(string);
		return NULL;
	}
	memcpy(str, *buffer, len);
	str[len] = '\0';

	(*buffer) = (*buffer)+len; // Skip past the string
	*buff_len -= len; // Reduce buffer length

	string->str = str;
	string->len = len;

	return string;
}

static long long int
decode_int(unsigned char **buffer, size_t *buff_len)
{
	char *endp;

	long long i = strtoll((char*)*buffer, &endp, 10);
	*buff_len -= (endp - (char*)*buffer);
	*buffer = (unsigned char*)endp;

	return i;
}

void*
decode(unsigned char **buffer, size_t *len, be_type *type)
{
	switch(**buffer) {
		case '0'...'9': {
			be_string *str = decode_str(buffer, len);
			*type = BE_STR;
			return str;
		}
		case 'i': {
			--(*len); ++(*buffer); // Consume 'i'
			long long i = decode_int(buffer, len);
			--(*len); ++(*buffer); // Consume 'e'
			*type = BE_INT;
			return (void*)i;
		}
		case 'l': {
			be_list *list = NULL;
			--(*len); ++(*buffer); // Consume 'l'
			if(*len<=0) return NULL;
			while(**buffer!='e') {
				be_type val_type = -1;
				void *val = decode(buffer, len, &val_type);

				// val can be 0 if it is an integer so check for type
				if(val==NULL && val_type!=BE_INT) {
					list_free(list);
					return NULL;
				}

				be_node node;
				node.type = val_type;
				node.key = NULL; // Key will be NULL for elements of a list
				node.val = val;

				if(list==NULL) list = list_create(node);
				else list = list_add(list, node);
			}
			*type = BE_LIST;
			--(*len); ++(*buffer); // Consume 'e'
			return list;
		}
		case 'd': {
			be_dict *dict = dict_create();
			if(dict==NULL) return dict;
			--(*len); ++(*buffer); // Consume 'd'
			while(**buffer!='e') {
				be_type val_type = -1;
				unsigned char *key = NULL; void *val = NULL;

				be_string *string = decode_str(buffer, len);
				if(string==NULL) {
					free(key);
					dict_destroy(dict);
					return NULL;
				}
				key = string->str;
				free(string); // We don't need the struct pointer now

				if(*len<=0 || key==NULL) {
					free(key);
					dict_destroy(dict);
					return NULL;
				}

				// To copy the buffer later if the value is found to
				// be the info dictionary
				unsigned char *orig_buff = *buffer;

				val = decode(buffer, len, &val_type);

				if((val==NULL && val_type!=BE_INT) || *len<=0) {
					free(key);
					dict_destroy(dict);
					return NULL;
				}

				if(dict_set(dict, key, val, val_type)==NULL) {
					free(key);
					dict_destroy(dict);
					return NULL;
				}

				// If the key is info and it's a dictionary, save the sha1
				// hash for later use
				if(strcmp("info", (char*)key)==0 && val_type==BE_DICT) {
					// The length of info dictionary
					size_t len = (*buffer - orig_buff);
					// Note that the 'len' argument means only the first
					// 'len' bytes from orig_buff are hashed, that is,
					// only the bencoded info dictionary till the 'e'
					SHA1(orig_buff, len, dict->info_hash);
					dict->has_info_hash = true;
				}
			}
			*type = BE_DICT;
			--(*len); ++(*buffer); // Consume 'e'
			return dict;
		}
		default: {
			*type = -1;
			return NULL;
		}
	}
}

void
hex_dump(unsigned char *str, size_t len)
{
	for(size_t i=0; i<len; ++i) {
		printf("%02X", str[i]);
	}
	printf("\n");
}

void
dict_val_print(unsigned char *key, void *val, be_type type)
{
	if(key!=NULL) printf("%s: ", key);
	switch(type) {
		case BE_STR: {
			be_string *string = val;
			// If the key is pieces, print the bytes in hex form by default
			if(key!=NULL && strcmp("pieces", (char*)key)==0) {
				hex_dump(string->str, string->len);
			}
			else printf("%s\n", string->str);
			break;
		}
		case BE_INT: {
			printf("%lld\n", (long long int)val);
			break;
		}
		case BE_LIST: {
			printf("[\n");
			be_list *list = val;
			while(list!=NULL) {
				dict_val_print(NULL, list->node.val, list->node.type);
				list = list->next;
			}
			printf("]\n");
			break;
		}
		case BE_DICT: {
			printf("{\n");
			dict_dump(val);
			printf("}\n");
			break;
		}
	}
}

be_dict*
decode_file(const char *file)
{
	struct stat st;
	FILE *fp = fopen(file, "rb");
	size_t len = 0;
	unsigned char *buffer, *stored_buff;
	be_dict *dict = NULL;

	if(fp==NULL) return NULL;

	if(stat(file, &st)) return NULL;

	len = st.st_size;

	if(len<=0) return NULL;

	buffer = malloc(len+1);
	if(buffer==NULL) return NULL;
	if(fread(buffer, 1, len, fp)<len) {
		free(buffer);
		fclose(fp);
		return NULL;
	}
	buffer[len] = '\0';

	stored_buff = buffer; // For freeing after decoding

	be_type type = -1;
	dict = decode(&buffer, &len, &type);
	if(type!=BE_DICT || dict==NULL) {
		// Free the node if the returned value is not a dictionary
		free(dict);
		free(stored_buff);
		fclose(fp);
		return NULL;
	}

	free(stored_buff);
	fclose(fp);
	return dict;
}
