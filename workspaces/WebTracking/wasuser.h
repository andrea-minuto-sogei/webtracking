#ifndef WASUSER_H_
#define WASUSER_H_

typedef unsigned char ltpakey_t[16];

typedef unsigned char* byte_p;

#define MAX_ATTRIBUTES 32

typedef struct
{
   unsigned int length;
   byte_p attrs[MAX_ATTRIBUTES];
   byte_p values[MAX_ATTRIBUTES];
} ltpa_t;

/*
* password: LTPA Keys Password
* tripledeskey: LTPA 3DES Key
* ltpakey: LTPA AES Key (Output)
* return: 0 = OK, 1 = LTPA 3DES Key not valid
*/
int prepareltpakey(unsigned char *, unsigned char *, ltpakey_t *);

/*
* ltpatoken: LTPA Token
* ltpakey: LTPA AES Key
* ltpadata: LTPA Decoded (Output)
* return: 0 = OK, 1 = LTPA Token not valid
*/
int ltpadecode(const unsigned char *ltpatoken, ltpakey_t ltpakey, ltpa_t *);

/*
* ltpa: LTPA Decoded
*/
void ltparelease(ltpa_t *);

#endif /* WASUSER_H_ */
