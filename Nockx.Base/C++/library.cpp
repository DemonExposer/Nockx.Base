#include "library.h"

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

unsigned char generate_ml_kem_key() {
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();

	EVP_PKEY *kem_key = EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-KEM-768");

	if (!kem_key) {
		fprintf(stderr, "Error generating key:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	FILE *file = fopen("ml_kem_private_key.pem", "w");
	if (!file) {
		perror("fopen");
		return 0;
	}

	if (!PEM_write_PrivateKey(file, kem_key, nullptr, nullptr, 0, nullptr, nullptr)) {
		fprintf(stderr, "Error writing private key:\n");
		ERR_print_errors_fp(stderr);
		fclose(file);
		return 0;
	}
	fclose(file);

	file = fopen("ml_kem_public_key.pem", "w");
	if (!file) {
		perror("fopen");
		return 0;
	}

	if (!PEM_write_PUBKEY(file, kem_key)) {
		fprintf(stderr, "Error writing public key:\n");
		ERR_print_errors_fp(stderr);
		fclose(file);
		return 0;
	}
	fclose(file);

	EVP_PKEY_free(kem_key);
	return 1;
}

unsigned char get_ciphertext_and_shared_secret_length(const unsigned char *kem_key, const unsigned int kem_key_size, unsigned int *ciphertext_length, unsigned int *shared_secret_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &kem_key, kem_key_size);
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
	EVP_PKEY_encapsulate(ctx, nullptr, &ct_length, nullptr, &ss_length);

	*ciphertext_length = ct_length;
	*shared_secret_length = ss_length;

	return 1;
}

unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *kem_key, unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, const unsigned int wrapped_encrypted_aes_key_length, const unsigned int shared_secret_length) {
	EVP_PKEY *parsed_key = d2i_PUBKEY(nullptr, &kem_key, kem_key_size);
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

	// - 32 because of the AES key size of 256 bits
	auto ciphertext = static_cast<unsigned char *>(OPENSSL_malloc(wrapped_encrypted_aes_key_length - 32));
	auto shared_secret = static_cast<unsigned char *>(OPENSSL_malloc(shared_secret_length));

	size_t ct_length = wrapped_encrypted_aes_key_length - 32;
	size_t ss_length = shared_secret_length;

	if (EVP_PKEY_encapsulate(ctx, ciphertext, &ct_length, shared_secret, &ss_length) <= 0) {
		fprintf(stderr, "Failed to encapsulate:\n");
		ERR_print_errors_fp(stderr);
		return 0;
	}

	if (wrapped_encrypted_aes_key_length - 32 != ct_length || shared_secret_length != ss_length) {
		fprintf(stderr, "Ciphertext and shared secret length mismatch!\n");
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