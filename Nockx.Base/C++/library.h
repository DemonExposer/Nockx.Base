#ifndef NOCKX_BASE_CPP_LIBRARY_H
#define NOCKX_BASE_CPP_LIBRARY_H

extern "C" {
	unsigned char generate_key(const char *key_type);

	unsigned char get_key_sizes_from_file(const char *file_name, int *key_type_name_size, int *public_key_size, int *private_key_size);

	unsigned char read_key_from_file(const char *file_name, char *key_type, unsigned char *public_key, unsigned char *private_key);

	unsigned char get_ciphertext_and_shared_secret_length(const unsigned char *public_kem_key, unsigned int kem_key_size, unsigned int *ciphertext_length, unsigned int *shared_secret_length);

	unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, unsigned int wrapped_encrypted_aes_key_length, unsigned int shared_secret_length);

	unsigned char decrypt_aes_key_with_ml_kem(const unsigned char *private_kem_key, unsigned int kem_key_size, const unsigned char *ciphertext, unsigned int ciphertext_length, unsigned char *decrypted_aes_key);

	unsigned char get_signature_size(const unsigned char *private_key, int key_size, const unsigned char *data, unsigned long data_size, unsigned int *signature_size);

	unsigned char sign_with_ml_dsa(const unsigned char *private_key, int key_size, const unsigned char *data, unsigned long data_size, unsigned char *signature, unsigned int *signature_size);

	int verify_with_ml_dsa(const unsigned char *public_key, int key_size, const unsigned char *data, unsigned long data_size, unsigned char *signature, unsigned int signature_size);
}

#endif // NOCKX_BASE_CPP_LIBRARY_H