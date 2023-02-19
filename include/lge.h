#include "openssl/asn1.h"
#include "openssl/asn1t.h"
#include "openssl/x509.h"
#include "openssl/evp.h"
#include "openssl/err.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"

#define SECURITY_VERSION_OLD       0x00000010
#define SECURITY_VERSION_2015      0x00000011
#define SECURITY_MAGIC1            0xA16E62C9
#define SECURITY_MAGIC2            0xD5E7FE61
#define SECURITY_MD_MAX_HASH_SIZE  32 // sha1,sha256 only
#define SECURITY_RSA_MAX_SIGN_SIZE 512 // 1024,2048,4096

#define LGFTM_BLUNLOCK_KEY_SIZE                1024

typedef struct key_st
{
	X509_ALGOR *algorithm_id;
	RSA *key_material;
}KEY;

typedef struct keybag_st
{
	KEY *mykey;
}KEYBAG;

typedef struct lge_keystore_st
{
	ASN1_INTEGER *version;
	ASN1_PRINTABLESTRING *keyalias;
	KEYBAG *mykeybag;
}LGE_KEYSTORE;

typedef struct killswitch_sig_st
{
	ASN1_INTEGER *version;
	X509_ALGOR *algor;
	ASN1_PRINTABLESTRING *keyalias;
	ASN1_OCTET_STRING *sig;
}KILLSWITCH_SIG;

#define IMPLEMENT_ASN1_ENCODE_FUNCTIONS_fname(stname, itname, fname) \
	stname *d2i_##fname(stname **a, const unsigned char **in, long len) \
	{ \
		return (stname *)ASN1_item_d2i((ASN1_VALUE **)a, in, len, ASN1_ITEM_rptr(itname));\
	} \
	int i2d_##fname(stname *a, unsigned char **out) \
	{ \
		return ASN1_item_i2d((ASN1_VALUE *)a, out, ASN1_ITEM_rptr(itname));\
	}

#define IMPLEMENT_ASN1_FUNCTIONS(stname) IMPLEMENT_ASN1_FUNCTIONS_fname(stname, stname, stname)

struct md_info {
	const EVP_MD* md; // The EVP_MD type is a structure for digest method implementation.
	const char* name; // md5, sha1, sha256
};

typedef struct verifystate_st
{
	const char* name;
	RSA* key;
	struct md_info md;
	unsigned char* image_addr;
	uint32_t image_size;
	unsigned char* signature_addr;
	int ret;
} VERIFY_CTX;

typedef struct
{
	char device_id[96];
	char imei[32];
} unlock_input_data_type;

typedef struct
{
	uint32_t magic1; // 0x8DB7159E
	uint32_t magic2; // 0x2D7ED36B
	uint32_t version; // 1
	uint32_t hash_type; // sha256
	uint32_t key_size; // rsa256
	unsigned char signature[256]; // raw signature
	unsigned char someOtherBytes[12];
	unsigned char signature2[256]; // raw signature
	unsigned char extra[480];
} unlock_certificate_data_type;

enum {
	SECURITY_ERROR_NONE           = 1000,
	SECURITY_ERROR_BOOTIMG_HDR    = 1001,
	SECURITY_ERROR_KERNEL_ADDR    = 1002,
	SECURITY_ERROR_CERTIFICATE    = 1003,
	SECURITY_ERROR_HASH_TYPE      = 1004,
	SECURITY_ERROR_KEYSTORE       = 1005,
	SECURITY_ERROR_VERIFY_KERNEL  = 1006,
	SECURITY_ERROR_VERIFY_RAMDISK = 1007,
	SECURITY_ERROR_VERIFY_DT      = 1008,
	SECURITY_ERROR_VERIFY_BOOTIMG = 1009,
	SECURITY_ERROR_NO_MEMORY      = 1010,
	SECURITY_ERROR_UNLOCK         = 1011,
	SECURITY_ERROR_HASH           = 1012,
	SECURITY_ERROR_PUBLIC_KEY     = 1013,
	SECURITY_ERROR_UNKNOWN,
	SECURITY_ERROR_MAX,
};

enum {
	CRYPTO_AUTH_ALG_MD5     = 0, // DO NOT USE
	CRYPTO_AUTH_ALG_SHA1    = 1,
	CRYPTO_AUTH_ALG_SHA256
};

enum {
	VERIFY_ERROR_NONE             = 2000,
	VERIFY_ERROR_PARAM            = 2001,
	VERIFY_ERROR_PUBLIC_KEY       = 2002,
	VERIFY_ERROR_HASH             = 2003,
	VERIFY_ERROR_SIG              = 2004,
};
struct X509_sig_st {
	X509_ALGOR *algor;
	ASN1_OCTET_STRING *digest;
};
