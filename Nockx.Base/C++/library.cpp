#include "library.h"

#include <vector>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

unsigned char generate_key(const char *key_type) {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	EVP_PKEY *key = EVP_PKEY_Q_keygen(nullptr, nullptr, key_type);

	if (!key) {
		fprintf(stderr, "Error generating key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	std::string key_type_str(key_type);
	std::ranges::transform(key_type_str, key_type_str.begin(), tolower);
	FILE *file = fopen((key_type_str + std::string("_private_key.pem")).c_str(), "w");
	if (!file) {
		perror("fopen");
		return 0;
	}

	if (!PEM_write_PrivateKey(file, key, nullptr, nullptr, 0, nullptr, nullptr)) {
		fprintf(stderr, "Error writing private key:\n");
		ERR_print_errors_fp(stderr);
		fclose(file);
		return 0;
	}
	fclose(file);

	file = fopen((key_type_str + std::string("_public_key.pem")).c_str(), "w");
	if (!file) {
		perror("fopen");
		return 0;
	}

	if (!PEM_write_PUBKEY(file, key)) {
		fprintf(stderr, "Error writing public key:\n");
		ERR_print_errors_fp(stderr);
		fclose(file);
		return 0;
	}
	fclose(file);

	EVP_PKEY_free(key);
	return 1;
}

unsigned char get_key_sizes_from_file(const char *file_name, int *key_type_name_size, int *public_key_size, int *private_key_size) {
	FILE *file = fopen(file_name, "r");
	if (!file) {
		perror("fopen");
		return 0;
	}

	EVP_PKEY *key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	*private_key_size = i2d_PrivateKey(key, nullptr);
	*public_key_size = i2d_PUBKEY(key, nullptr);
	*key_type_name_size = static_cast<int>(strlen(EVP_PKEY_get0_type_name(key)));
	EVP_PKEY_free(key);

	return 1;
}

unsigned char read_key_from_file(const char *file_name, char *key_type, unsigned char *public_key, unsigned char *private_key) {
	FILE *file = fopen(file_name, "r");
	if (!file) {
		perror("fopen");
		return 0;
	}

	EVP_PKEY *key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
	fclose(file);
	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	const char *name = EVP_PKEY_get0_type_name(key);
	strcpy(key_type, name);

	i2d_PrivateKey(key, &private_key);
	i2d_PUBKEY(key, &public_key);
	EVP_PKEY_free(key);

	return 1;
}

unsigned char get_ciphertext_and_shared_secret_length(const unsigned char *public_kem_key, const unsigned int kem_key_size, unsigned int *ciphertext_length, unsigned int *shared_secret_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_kem_key, kem_key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(parsed_key, nullptr);
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
		fprintf(stderr, "Failed to initialize encapsulation:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	size_t ct_length, ss_length;
	if (EVP_PKEY_encapsulate(ctx, nullptr, &ct_length, nullptr, &ss_length) <= 0) {
		fprintf(stderr, "Failed to encapsulate (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	*ciphertext_length = ct_length;
	*shared_secret_length = ss_length;

	return 1;
}

unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, const unsigned int wrapped_encrypted_aes_key_length, const unsigned int shared_secret_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_kem_key, kem_key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(parsed_key, nullptr);
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_PKEY_encapsulate_init(ctx, nullptr) <= 0) {
		fprintf(stderr, "Failed to initialize encapsulation:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	// - 32 because of the AES key size of 256 bits
	auto ciphertext = static_cast<unsigned char *>(OPENSSL_malloc(wrapped_encrypted_aes_key_length - 32));
	auto shared_secret = static_cast<unsigned char *>(OPENSSL_malloc(shared_secret_length));

	size_t ct_length = wrapped_encrypted_aes_key_length - 32;
	size_t ss_length = shared_secret_length;

	if (EVP_PKEY_encapsulate(ctx, ciphertext, &ct_length, shared_secret, &ss_length) <= 0) {
		fprintf(stderr, "Failed to encapsulate:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (wrapped_encrypted_aes_key_length - 32 != ct_length || shared_secret_length != ss_length) {
		fprintf(stderr, "Ciphertext and shared secret length mismatch!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	for (int i = 0; i < 32; i++)
		wrapped_encrypted_aes_key[i] = aes_key[i] ^ shared_secret[i];

	for (int i = 32; i < wrapped_encrypted_aes_key_length; i++)
		wrapped_encrypted_aes_key[i] = ciphertext[i - 32];

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);
	OPENSSL_free(ciphertext);
	OPENSSL_free(shared_secret);

	return 1;
}

unsigned char decrypt_aes_key_with_ml_kem(const unsigned char *private_kem_key, const unsigned int kem_key_size, const unsigned char *ciphertext, const unsigned int ciphertext_length, unsigned char *decrypted_aes_key) {
	EVP_PKEY *parsed_key = d2i_PrivateKey(OBJ_txt2nid("ML-KEM-768"), nullptr, &private_kem_key, kem_key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(parsed_key, nullptr);
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_PKEY_decapsulate_init(ctx, nullptr) <= 0) {
		fprintf(stderr, "Failed to initialize decapsulation:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	size_t ss_length;
	std::vector encrypted_aes_key(ciphertext, ciphertext + 32);
	std::vector true_ciphertext(ciphertext + 32, ciphertext + ciphertext_length);
	if (EVP_PKEY_decapsulate(ctx, nullptr, &ss_length, true_ciphertext.data(), true_ciphertext.size()) <= 0) {
		fprintf(stderr, "Failed to decapsulate (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	std::vector<uint8_t> shared_secret(ss_length);
	if (EVP_PKEY_decapsulate(ctx, shared_secret.data(), &ss_length, true_ciphertext.data(), true_ciphertext.size()) <= 0) {
		fprintf(stderr, "Failed to decapsulate:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	for (int i = 0; i < shared_secret.size(); i++)
		decrypted_aes_key[i] = shared_secret[i] ^ encrypted_aes_key[i];

	return 1;
}

unsigned char get_signature_size(const unsigned char *private_key, const int key_size, const unsigned char *data, unsigned long data_size, unsigned int *signature_size) {
	EVP_PKEY *parsed_key = d2i_PrivateKey(OBJ_txt2nid("ML-DSA-65"), nullptr, &private_key, key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	size_t sig_size;
	if (EVP_DigestSign(ctx, nullptr, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign (size check):\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	*signature_size = sig_size;

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return 1;
}

unsigned char sign_with_ml_dsa(const unsigned char *private_key, const int key_size, const unsigned char *data, const unsigned long data_size, unsigned char *signature, unsigned int *signature_size) {
	EVP_PKEY *parsed_key = d2i_PrivateKey(OBJ_txt2nid("ML-DSA-65"), nullptr, &private_key, key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize signing:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	if (EVP_DigestSign(ctx, signature, reinterpret_cast<size_t *>(signature_size), data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return 0;
	}

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return 1;
}

int verify_with_ml_dsa(const unsigned char *public_key, const int key_size, const unsigned char *data, unsigned long data_size, unsigned char *signature, unsigned int signature_size) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &public_key, key_size);
	if (!parsed_key) {
		fprintf(stderr, "Failed to parse key:\n");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		fprintf(stderr, "Failed to create context:\n");
		ERR_print_errors_fp(stderr);
		EVP_PKEY_free(parsed_key);
		return -1;
	}

	if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, parsed_key) <= 0) {
		fprintf(stderr, "Failed to initialize verifying:\n");
		ERR_print_errors_fp(stderr);
		EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		return -1;
	}

	int result = EVP_DigestVerify(ctx, signature, signature_size, data, data_size);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(parsed_key);

	return result;
}