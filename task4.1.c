#include <stdio.h>
#include <openssl/bn.h>
#define NBITS 256
void printBN(char *msg, BIGNUM *a)
{
/*Use BN_bn2hex(a) for hex string
*Use BN_bn2dec(a) for decimal string*/
char *number_str = BN_bn2hex(a);
printf("%s %s\n", msg, number_str);
OPENSSL_free(number_str);
}
int main ()
{
BN_CTX *ctx = BN_CTX_new();
BIGNUM *m = BN_new();
BIGNUM *n = BN_new();
BIGNUM *d = BN_new();
BIGNUM *e = BN_new();
BIGNUM *res = BN_new();
// Initialize a, b, n
//BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
//signing a messag means apply RSA function with the private key on message
//S = R(m,d) = m^d mod n
//message = kelvin owe you $2000
//message in hex = C260FFEB526F5146DD83F0A3896069E6E58E461C8B91A19DDAEC3CEBF026E272
BN_hex2bn(&m, "C260FFEB526F5146DD83F0A3896069E6E58E461C8B91A19DDAEC3CEBF026E272");
BN_hex2bn(&n, 
"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&d, 
"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&e, "010001");
//calculate res = m^d mod n and print it as s
BN_mod_exp(res, m, d, n, ctx);
printBN("s = ", res);
//message = kelvin owe you $3000
//message in hex = C260FFEB526F5146DD83F0A3896069E6E58E461C8B91A19DDAEC3CEBF026E272
BN_hex2bn(&m, "C260FFEB526F5146DD83F0A3896069E6E58E461C8B91A19DDAEC3CEBF026E272");
BN_hex2bn(&n, 
"DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
BN_hex2bn(&d, 
"74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");
BN_hex2bn(&e, "010001");
//calculate res = m^d mod n and print it as s
BN_mod_exp(res, m, d, n, ctx);
printBN("s = ", res);
return 0;
}