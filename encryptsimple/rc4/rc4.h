#include "./../stdafx.h"
typedef struct rc4_key_t {
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} rc4_key_t;



void rc4_set_key(const unsigned char *key_data, size_t key_data_len, rc4_key_t * key);
void rc4_crypt(unsigned char *buffer, size_t buffer_len, rc4_key_t * key);
