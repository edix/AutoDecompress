#include "stdafx.h"

void rc4_set_key(const unsigned char *buf, size_t len, rc4_key_t * key)
{
	unsigned char j = 0;
	unsigned char *state = key->state;
	int i;

	for (i = 0; i < 256; ++i)
		state[i] = i;

	key->x = 0;
	key->y = 0;

	for (i = 0; i < 256; ++i) 
	{
		j = j + state[i] + buf[i % len];
		std::swap(state[i], state[j]);
	}
}

void rc4_crypt(unsigned char *buf, size_t len, rc4_key_t * key)
{
	unsigned char x;
	unsigned char y;
	unsigned char *state = key->state;
	unsigned int  i;

	x = key->x;
	y = key->y;

	for (i = 0; i < len; i++) 
	{
		y = y + state[++x];
		std::swap(state[x], state[y]);
		buf[i] ^= state[(state[x] + state[y]) & 0xff];
	}

	key->x = x;
	key->y = y;
}
