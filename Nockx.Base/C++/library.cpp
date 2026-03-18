#include "library.h"

#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/decoder.h>

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
	EVP_PKEY_free(key);

	return 1;
}

unsigned char get_key_sizes_from_file(const char *file_name, const char *key_type, int *public_key_size, int *private_key_size) {
	BIO *bio = BIO_new_file(file_name, "r");
	if (!bio) {
		fprintf(stderr, "Error opening private key file:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	*private_key_size = i2d_PrivateKey(key, nullptr);
	*public_key_size = i2d_PUBKEY(key, nullptr);
	EVP_PKEY_free(key);
	BIO_free(bio);

	return 1;
}

unsigned char read_key_from_file(const char *file_name, const char *key_type, unsigned char *public_key, unsigned char *private_key) {
	BIO *bio = BIO_new_file(file_name, "r");
	if (!bio) {
		fprintf(stderr, "Error opening private key file:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	i2d_PrivateKey(key, &private_key);
	i2d_PUBKEY(key, &public_key);
	EVP_PKEY_free(key);
	BIO_free(bio);

	return 1;
}

unsigned char get_public_key_size_from_string(const char *input, const char *key_type, int *public_key_size) {
	BIO *bio = BIO_new_mem_buf(input, static_cast<int>(strlen(input)));
	if (!bio) {
		fprintf(stderr, "Error creating buffer for public key string:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	*public_key_size = i2d_PUBKEY(key, nullptr);
	EVP_PKEY_free(key);
	BIO_free(bio);

	return 1;
}

unsigned char read_public_key_from_string(const char *input, const char *key_type, unsigned char *public_key) {
	BIO *bio = BIO_new_mem_buf(input, static_cast<int>(strlen(input)));
	if (!bio) {
		fprintf(stderr, "Error creating buffer for public key string:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	EVP_PKEY *key = nullptr;
	EVP_PKEY *candidate = nullptr;
	while ((candidate = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr)) != nullptr) {
		if (strcmp(EVP_PKEY_get0_type_name(candidate), key_type) == 0) {
			key = candidate;
			break;
		}
		EVP_PKEY_free(candidate);
	}

	if (!key) {
		fprintf(stderr, "Error reading key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	i2d_PUBKEY(key, &public_key);
	EVP_PKEY_free(key);
	BIO_free(bio);

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

unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, const unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, const unsigned int wrapped_encrypted_aes_key_length, const unsigned int shared_secret_length) {
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
		OPENSSL_free(ciphertext);
		OPENSSL_free(shared_secret);
		return 0;
	}

	if (wrapped_encrypted_aes_key_length - 32 != ct_length || shared_secret_length != ss_length) {
		fprintf(stderr, "Ciphertext and shared secret length mismatch!\n");
		EVP_PKEY_CTX_free(ctx);
		EVP_PKEY_free(parsed_key);
		OPENSSL_free(ciphertext);
		OPENSSL_free(shared_secret);
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

unsigned char decrypt_aes_key_with_ml_kem(const unsigned char *private_kem_key, uint64_t kem_key_size, const unsigned char *ciphertext, const unsigned int ciphertext_length, unsigned char *decrypted_aes_key) {
	EVP_PKEY *parsed_key = nullptr;
	OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&parsed_key, "DER", nullptr, "ML-KEM-768", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
	size_t key_size_t = kem_key_size;
	OSSL_DECODER_from_data(dctx, &private_kem_key, &key_size_t);
	OSSL_DECODER_CTX_free(dctx);

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
	std::vector<unsigned char> encrypted_aes_key(ciphertext, ciphertext + 32);
	std::vector<unsigned char> true_ciphertext(ciphertext + 32, ciphertext + ciphertext_length);
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

unsigned char get_signature_size(const unsigned char *private_key, const uint64_t key_size, const unsigned char *data, const uint64_t data_size, uint64_t *signature_size) {
	EVP_PKEY *parsed_key = nullptr;
	OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&parsed_key, "DER", nullptr, "ML-DSA-65", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
	size_t key_size_t = key_size;
	OSSL_DECODER_from_data(dctx, &private_key, &key_size_t);
	OSSL_DECODER_CTX_free(dctx);

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

unsigned char sign_with_ml_dsa(const unsigned char *private_key, const uint64_t key_size, const unsigned char *data, const uint64_t data_size, unsigned char *signature, uint64_t *signature_size) {
	EVP_PKEY *parsed_key = nullptr;
	OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&parsed_key, "DER", nullptr, "ML-DSA-65", OSSL_KEYMGMT_SELECT_PRIVATE_KEY, nullptr, nullptr);
	size_t key_size_t = key_size;
	OSSL_DECODER_from_data(dctx, &private_key, &key_size_t);
	OSSL_DECODER_CTX_free(dctx);

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

	size_t sig_size = *signature_size;
	if (EVP_DigestSign(ctx, signature, &sig_size, data, data_size) <= 0) {
		fprintf(stderr, "Failed to sign:\n");
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

int verify_with_ml_dsa(const unsigned char *public_key, const int key_size, const unsigned char *data, const uint64_t data_size, const unsigned char *signature, const unsigned int signature_size) {
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