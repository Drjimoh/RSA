/* bn_sample.c */
#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM * m)
{
/* Use BN_bn2hex(a) for hex string
* Use BN_bn2dec(a) for decimal string */
char * number_str = BN_bn2hex(m);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *p = BN_new();
BIGNUM *q = BN_new();
BIGNUM *n = BN_new();
BIGNUM *m = BN_new();
BIGNUM *res = BN_new();

// Initialize a, b, n
//BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&e, "010001");
BN_hex2bn(&m, "A to secret!");
BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
//BN_rand(n, NBITS, 0, 0);

// res = mˆb mod n
BN_mod_exp(res, m, e, n, ctx);
printBN("mˆe mod n = ", res);
// decrypt = mˆb mod n

BN_mod_exp(res, m, d, n, ctx);
printBN("pˆc mod n = ", res);

return 0;
}
