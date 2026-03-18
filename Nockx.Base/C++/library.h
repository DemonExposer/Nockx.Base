#ifndef NOCKX_BASE_CPP_LIBRARY_H
#define NOCKX_BASE_CPP_LIBRARY_H

#include <cstdint>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

extern "C" {
	EXPORT unsigned char generate_key(const char *key_type);

	EXPORT unsigned char get_key_sizes_from_file(const char *file_name, const char *key_type, int *public_key_size, int *private_key_size);

	EXPORT unsigned char read_key_from_file(const char *file_name, const char *key_type, unsigned char *public_key, unsigned char *private_key);

	EXPORT unsigned char get_public_key_size_from_string(const char *input, const char *key_type, int *public_key_size);

	EXPORT unsigned char read_public_key_from_string(const char *input, char *key_type, unsigned char *public_key);

	EXPORT unsigned char get_ciphertext_and_shared_secret_length(const unsigned char *public_kem_key, unsigned int kem_key_size, unsigned int *ciphertext_length, unsigned int *shared_secret_length);

	EXPORT unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, unsigned int wrapped_encrypted_aes_key_length, unsigned int shared_secret_length);

	EXPORT unsigned char decrypt_aes_key_with_ml_kem(const unsigned char *private_kem_key, uint64_t kem_key_size, const unsigned char *ciphertext, unsigned int ciphertext_length, unsigned char *decrypted_aes_key);

	EXPORT unsigned char get_signature_size(const unsigned char *private_key, uint64_t key_size, const unsigned char *data, uint64_t data_size, uint64_t *signature_size);

	EXPORT unsigned char sign_with_ml_dsa(const unsigned char *private_key, uint64_t key_size, const unsigned char *data, uint64_t data_size, unsigned char *signature, uint64_t *signature_size);

	EXPORT int verify_with_ml_dsa(const unsigned char *public_key, int key_size, const unsigned char *data, uint64_t data_size, const unsigned char *signature, unsigned int signature_size);
}

#endif // NOCKX_BASE_CPP_LIBRARY_H