#include "lge.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <iostream>
#include <fstream>


DECLARE_ASN1_ENCODE_FUNCTIONS_const(RSA, RSAPublicKey)
DECLARE_ASN1_FUNCTIONS(X509_ALGOR)

ASN1_SEQUENCE(KILLSWITCH_SIG) = {
	ASN1_SIMPLE(KILLSWITCH_SIG, version, ASN1_INTEGER),
	ASN1_SIMPLE(KILLSWITCH_SIG, algor, X509_ALGOR),
	ASN1_SIMPLE(KILLSWITCH_SIG, keyalias, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(KILLSWITCH_SIG, sig, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(KILLSWITCH_SIG)
IMPLEMENT_ASN1_FUNCTIONS(KILLSWITCH_SIG)

ASN1_SEQUENCE(KEY) = {
	ASN1_SIMPLE(KEY, algorithm_id, X509_ALGOR),
	ASN1_SIMPLE(KEY, key_material, RSAPublicKey)
}ASN1_SEQUENCE_END(KEY)
IMPLEMENT_ASN1_FUNCTIONS(KEY);

ASN1_SEQUENCE(KEYBAG) = {
	ASN1_SIMPLE(KEYBAG, mykey, KEY)
}ASN1_SEQUENCE_END(KEYBAG)
IMPLEMENT_ASN1_FUNCTIONS(KEYBAG)

ASN1_SEQUENCE(LGE_KEYSTORE) = {
	ASN1_SIMPLE(LGE_KEYSTORE, version, ASN1_INTEGER),
	ASN1_SIMPLE(LGE_KEYSTORE, keyalias, ASN1_PRINTABLESTRING),
	ASN1_SIMPLE(LGE_KEYSTORE, mykeybag, KEYBAG)
} ASN1_SEQUENCE_END(LGE_KEYSTORE)
IMPLEMENT_ASN1_FUNCTIONS(LGE_KEYSTORE)

const unsigned char BLUNLOCK_KEYSTORE[] = {
	0x30, 0x82, 0x01, 0x35, 0x02, 0x01, 0x00, 0x13, 0x0d, 0x55, 0x4e, 0x4c,
	0x4f, 0x43, 0x4b, 0x5f, 0x52, 0x53, 0x41, 0x5f, 0x30, 0x32, 0x30, 0x82,
	0x01, 0x1f, 0x30, 0x82, 0x01, 0x1b, 0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x30, 0x82, 0x01, 0x0a, 0x02,
	0x82, 0x01, 0x01, 0x00, 0x92, 0xd5, 0xe3, 0xa2, 0xc6, 0xf3, 0x11, 0xa1,
	0xfd, 0x32, 0x5c, 0x94, 0x41, 0x5d, 0xf1, 0x97, 0xba, 0x1c, 0x2b, 0x30,
	0x7c, 0x1e, 0xdb, 0xb5, 0xd9, 0xed, 0x10, 0x9a, 0xb8, 0xa6, 0x39, 0xf1,
	0x0d, 0x61, 0xf6, 0x58, 0x2b, 0x36, 0x7a, 0xae, 0xcb, 0xbf, 0x95, 0xa1,
	0x30, 0xe5, 0x47, 0x54, 0x66, 0x75, 0x65, 0xaa, 0x6a, 0x60, 0xaf, 0xa6,
	0xad, 0xd6, 0xf2, 0x46, 0x04, 0x8c, 0x83, 0x9d, 0x01, 0x7d, 0x21, 0x84,
	0x9f, 0x5a, 0xa2, 0xa0, 0x8f, 0xa5, 0xdb, 0xde, 0x07, 0x12, 0x69, 0x4e,
	0x7e, 0x80, 0xfc, 0x42, 0xa7, 0x09, 0xce, 0xe3, 0xa9, 0x1a, 0x5b, 0x11,
	0x87, 0x3a, 0x07, 0x9e, 0x0f, 0xb0, 0x4e, 0x14, 0x00, 0x1c, 0x6b, 0x5b,
	0xb4, 0xa5, 0xdd, 0xf5, 0x2e, 0x79, 0x3a, 0x8d, 0x5d, 0xd4, 0xe1, 0x77,
	0xc5, 0x60, 0xc7, 0xce, 0xdf, 0xb8, 0xfc, 0xc8, 0x44, 0xb6, 0x64, 0x0b,
	0x48, 0x13, 0xd6, 0x29, 0xab, 0x9b, 0x34, 0xcf, 0xd5, 0x08, 0x1c, 0x5a,
	0x53, 0x84, 0x22, 0x50, 0x49, 0xfe, 0x0b, 0x62, 0xef, 0xbf, 0x79, 0x72,
	0x84, 0x21, 0x36, 0x0d, 0x3c, 0x87, 0x4b, 0x38, 0x7c, 0xe5, 0xb6, 0x78,
	0x91, 0xf8, 0x94, 0x2d, 0xb4, 0x31, 0xbe, 0xaa, 0xc7, 0x41, 0x4e, 0xd5,
	0x2a, 0xfa, 0x28, 0x3e, 0xa3, 0x9e, 0xad, 0x16, 0x0d, 0xa5, 0x1f, 0xd7,
	0xf8, 0x39, 0x3b, 0xaf, 0x6b, 0xbc, 0xa7, 0x80, 0xdf, 0xac, 0x47, 0x7b,
	0xfe, 0xf4, 0x3c, 0x61, 0xe9, 0x43, 0x1b, 0x85, 0xf7, 0x0e, 0x4d, 0xb2,
	0xcf, 0x7b, 0x0f, 0x7a, 0x41, 0x0d, 0xb2, 0x4d, 0x6f, 0x80, 0x6c, 0x91,
	0xa2, 0xc6, 0x50, 0x89, 0x7e, 0x9b, 0x90, 0x66, 0x8d, 0x25, 0xb0, 0xa9,
	0x17, 0x40, 0x54, 0xe1, 0x33, 0xb4, 0x38, 0x2a, 0xda, 0x5a, 0xec, 0x35,
	0x27, 0xd2, 0xf4, 0xca, 0xbe, 0x26, 0x39, 0x17, 0x02, 0x03, 0x01, 0x00,
	0x01
};

std::string hexStr(const uint8_t* data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}

static uint32_t read_der_message_length(unsigned char* input)
{
	uint32_t len = 0;
	int pos = 0;
	uint8_t len_bytes = 1;

	/* Check if input starts with Sequence id (0X30) */
	if (input[pos] != 0x30)
		return len;
	pos++;

	/* A length of 0xAABBCCDD in DER encoded messages would be sequence of
	following octets 0xAA, 0xBB, 0XCC, 0XDD.

	To read length - read each octet and shift left by 1 octect before
	reading next octet.
	*/
	/* check if short or long length form */
	if (input[pos] & 0x80)
	{
		len_bytes = (input[pos] & ~(0x80));
		pos++;
	}
	while (len_bytes)
	{
		/* Shift len by 1 octet */
		len = len << 8;

		/* Read next octet */
		len = len | input[pos];
		pos++; len_bytes--;
	}

	/* Add number of octets representing sequence id and length  */
	len += pos;

	return len;
}


static void get_md_info(int hash_type, struct md_info *info)
{
	switch (hash_type)
	{
#ifdef WIN32
		case CRYPTO_AUTH_ALG_MD5:
			info->md = EVP_md5();
			info->name = "md5";
			break;
#endif
		case CRYPTO_AUTH_ALG_SHA1:
			info->md = EVP_sha1();
			info->name = "sha1";
			break;
		case CRYPTO_AUTH_ALG_SHA256:
			info->md = EVP_sha256();
			info->name = "sha256";
			break;
		default:
			info->md = NULL;
			info->name = NULL;
			return;
	}
}
static bool verify_image(VERIFY_CTX* ctx)
{
	int key_size = 0;
	unsigned char md_value[EVP_MAX_MD_SIZE] = { 0, };
	uint32_t md_len = 0;
	unsigned char plain_text[EVP_MAX_MD_SIZE] = { 0, };
	int plain_len = 0;
	uint32_t len = 0;
	X509_SIG* sig = NULL;

	if (ctx == NULL ||
		ctx->md.md == NULL) {
		ctx->ret = VERIFY_ERROR_PARAM;
		goto err;
	}

#ifdef LGE_QCT_HW_CRYPTO
	if (strcmp(ctx->md.name, "sha1") == 0) {
		md_len = EVP_MD_size(ctx->md.md);
		hash_find(ctx->image_addr, ctx->image_size, md_value, CRYPTO_AUTH_ALG_SHA1);
	}
	else if (strcmp(ctx->md.name, "sha256") == 0) {
		md_len = EVP_MD_size(ctx->md.md);
		hash_find(ctx->image_addr, ctx->image_size, md_value, CRYPTO_AUTH_ALG_SHA256);
	}
	else {
		ctx->ret = VERIFY_ERROR_PARAM;
		goto err;
	}
#elif defined(LGE_NVA_HW_CRYPTO)
#error TODO
#elif defined(LGE_ODIN_HW_CRYPTO)
#define CRYS_HASH_SHA1_mode 0
#define CRYS_HASH_SHA256_mode 2
	if (strcmp(ctx->md.name, "sha1") == 0) {
		md_len = EVP_MD_size(ctx->md.md);
		hash_find(ctx->image_addr, ctx->image_size, md_value, CRYS_HASH_SHA1_mode);
	}
	else if (strcmp(ctx->md.name, "sha256") == 0) {
		md_len = EVP_MD_size(ctx->md.md);
		hash_find(ctx->image_addr, ctx->image_size, md_value, CRYS_HASH_SHA256_mode);
	}
	else {
		ctx->ret = VERIFY_ERROR_PARAM;
		goto err;
	}
#else
	if (EVP_Digest(ctx->image_addr, ctx->image_size, md_value, &md_len, ctx->md.md, NULL) != 1) {
		ctx->ret = VERIFY_ERROR_HASH;
		goto err;
	}
#endif

#ifdef WIN32
	//dump(ctx->image_addr, ctx->image_size);
#endif // WIN32

	if (ctx->key == NULL) {
		ctx->ret = VERIFY_ERROR_PARAM;
		goto err;
	}

	key_size = RSA_size(ctx->key);
	plain_len = RSA_public_decrypt(key_size, ctx->signature_addr, plain_text, ctx->key, RSA_PKCS1_PADDING);
	if (plain_len == -1) {
		ctx->ret = VERIFY_ERROR_PUBLIC_KEY;
		goto err;
	}

	std::cout << "Decrypted Hash: " << hexStr(plain_text, plain_len) << "\n";
	std::cout << "Expected hash: " << hexStr(md_value, md_len) << "\n";

	if (plain_len > (int)md_len)
	{
		len = read_der_message_length(plain_text);
		if (len > 0)
		{
			unsigned char* p = plain_text;
			sig = d2i_X509_SIG(NULL, (const unsigned char**)&p, len);
			if (sig == NULL ||
				sig->digest == NULL) {
				ctx->ret = VERIFY_ERROR_SIG;
				goto err;
			}

			if (sig->digest->length == (int)md_len && memcmp(md_value, sig->digest->data, md_len) == 0)
			{
				ctx->ret = VERIFY_ERROR_NONE;
				std::cout << "[INFO] " << ctx->name << " verified\n";
				goto err;
			}
		}
	}
	else
	{
		if (plain_len == (int)md_len && memcmp(md_value, plain_text, md_len) == 0)
		{
			ctx->ret = VERIFY_ERROR_NONE;
			std::cout << "[INFO] " << ctx->name << " verified\n";
			goto err;
		}
	}

	ctx->ret = VERIFY_ERROR_HASH;
	goto err;

err:
	if (sig != NULL) {
		X509_SIG_free(sig);
		sig = NULL;
	}

	if (ctx->ret == VERIFY_ERROR_NONE)
		return true;

	std::cout << "[CRITICAL] verify_image : " <<  ctx->ret << "\n";
	return false;
}

int main(int argc, char* argv[])
{   
	if (argc < 4)
	{
		std::cout << "Some arguments are missing.\n";
		std::cout << "Example Usage: " << argv[0] << " "
			<< "imei deviceId pathToUnlockBin\n";
		return 0;
	}

	std::string imei(argv[1]);
	std::string deviceId(argv[2]);
	std::string unlockBinPath(argv[3]);

	LGE_KEYSTORE *ks;
	unsigned char* in = const_cast<unsigned char*>(&BLUNLOCK_KEYSTORE[0]);

	uint32_t len = read_der_message_length(in);
	if (!len)
	{
		std::cout << "keystore length is invalid.\n";
		return 0;
	}

	ks = d2i_LGE_KEYSTORE(NULL, (const unsigned char**)&in, len);


	unlock_certificate_data_type *output = NULL;
	VERIFY_CTX verify_ctx = { 0, };

	//assert(sizeof(unlock_certificate_data_type) <= LGFTM_BLUNLOCK_KEY_SIZE)


	output = (unlock_certificate_data_type*)malloc(LGFTM_BLUNLOCK_KEY_SIZE);
	std::ifstream f1 (unlockBinPath, std::ios_base::binary);
	f1.read(reinterpret_cast<char*>(output), LGFTM_BLUNLOCK_KEY_SIZE);
	

	unlock_input_data_type input;
	memset(&input, 0x00, sizeof(unlock_input_data_type));
	memcpy(&input.imei, imei.c_str(), 
		std::min(sizeof(input.imei), imei.length()));
	memcpy(&input.device_id, deviceId.c_str(), 
		std::min(sizeof(input.device_id),deviceId.length()));

	verify_ctx.key = ks->mykeybag->mykey->key_material;
	verify_ctx.name = "unlock";
	verify_ctx.image_addr = (unsigned char*)&input;
	verify_ctx.image_size = sizeof(unlock_input_data_type);
	verify_ctx.signature_addr = output->signature;

	get_md_info(output->hash_type, &verify_ctx.md);

	verify_image(&verify_ctx);

}
