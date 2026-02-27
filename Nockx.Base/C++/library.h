#ifndef NOCKX_BASE_CPP_LIBRARY_H
#define NOCKX_BASE_CPP_LIBRARY_H

extern "C" unsigned char generate_ml_kem_key();

extern "C" unsigned char get_ciphertext_and_shared_secret_length(const unsigned char *public_kem_key, unsigned int kem_key_size, unsigned int *ciphertext_length, unsigned int *shared_secret_length);

extern "C" unsigned char encrypt_aes_key_with_ml_kem(const unsigned char *public_kem_key, unsigned int kem_key_size, const unsigned char *aes_key, unsigned char *wrapped_encrypted_aes_key, unsigned int wrapped_encrypted_aes_key_length, unsigned int shared_secret_length);

extern "C" unsigned char decrypt_aes_key_with_ml_kem(const unsigned char *private_kem_key, unsigned int kem_key_size, const unsigned char *ciphertext, unsigned int ciphertext_length, unsigned char *decrypted_aes_key);

#endif // NOCKX_BASE_CPP_LIBRARY_H