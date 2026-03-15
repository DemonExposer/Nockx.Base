using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes;

internal static partial class MlKemCryptography {
	[LibraryImport("libnockx-base")]
	private static partial byte generate_key([MarshalAs(UnmanagedType.LPStr)] string keyType);

	public static bool GenerateKey(string keyType) => generate_key(keyType) != 0;
	
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte get_key_sizes_from_file([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType, int *publicKeySize, int *privateKeySize);
	
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte read_key_from_file([MarshalAs(UnmanagedType.LPStr)] string fileName, [MarshalAs(UnmanagedType.LPStr)] string keyType, byte *publicKey, byte *privateKey);

	public static unsafe KeyPair ReadKeyFromFile(string fileName, string keyType) {
		int publicKeySize, privateKeySize;
		if (get_key_sizes_from_file(fileName, keyType, &publicKeySize, &privateKeySize) == 0)
			throw new Exception("Could not read key file: " + fileName);
		
		byte[] publicKey = new byte[publicKeySize];
		byte[] privateKey = new byte[privateKeySize];

		fixed (byte *publicKeyPointer = publicKey)
			fixed (byte *privateKeyPointer = privateKey)
				if (read_key_from_file(fileName, keyType, publicKeyPointer, privateKeyPointer) == 0)
					throw new Exception("Could not read key file: " + fileName);


		return new KeyPair {
			Type = new string(keyType),
			PublicKey = publicKey,
			PrivateKey = privateKey
		};
	}

	[LibraryImport("libnockx-base")]
	private static unsafe partial byte get_public_key_size_from_string([MarshalAs(UnmanagedType.LPStr)] string input, [MarshalAs(UnmanagedType.LPStr)] string keyType, int *publicKeySize);

	[LibraryImport("libnockx-base")]
	private static unsafe partial byte read_public_key_from_string([MarshalAs(UnmanagedType.LPStr)] string input, [MarshalAs(UnmanagedType.LPStr)] string keyType, byte *publicKey);

	public static unsafe byte[] ReadPublicKeyFromString(string input, string keyType) {
		int publicKeySize;
		if (get_public_key_size_from_string(input, keyType, &publicKeySize) == 0)
			throw new Exception("Could not read public key: " + input);
		
		byte[] publicKey = new byte[publicKeySize];

		fixed (byte *publicKeyPointer = publicKey)
			if (read_public_key_from_string(input, keyType, publicKeyPointer) == 0)
				throw new Exception("Could not read public key: " + input);


		return publicKey;
	}
	
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte get_ciphertext_and_shared_secret_length(byte *kemPublicKey, uint kemKeySize, uint *ciphertextLength, uint *sharedSecretLength);

	[LibraryImport("libnockx-base")]
	private static unsafe partial byte encrypt_aes_key_with_ml_kem(byte *kemPublicKey, uint kemKeySize, byte *aesKey, byte *wrappedEncryptedAesKey, uint wrappedEncryptedAesKeyLength, uint sharedSecretLength);

	public static unsafe byte[] EncryptAesKey(byte[] aesKey, byte[] publicKemKey) {
		byte[] encryptedAesKey;
		bool isSuccessful;
		fixed (byte *kemKeyPointer = publicKemKey) {
			uint ciphertextLength, sharedSecretLength;
			if (get_ciphertext_and_shared_secret_length(kemKeyPointer, (uint) publicKemKey.Length, &ciphertextLength, &sharedSecretLength) == 0)
				throw new Exception("Could not get output sizes");
			
			encryptedAesKey = new byte[Cryptography.AesKeyLength + ciphertextLength];
			
			fixed (byte *aesKeyPointer = aesKey)
				fixed (byte *encryptedAesKeyPointer = encryptedAesKey)
					isSuccessful = encrypt_aes_key_with_ml_kem(kemKeyPointer, (uint) publicKemKey.Length, aesKeyPointer, encryptedAesKeyPointer, (uint) encryptedAesKey.Length, sharedSecretLength) != 0;
		}

		return !isSuccessful ? throw new Exception("Could not encrypt AES key") : encryptedAesKey;
	}
	
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte decrypt_aes_key_with_ml_kem(byte *kemPrivateKey, ulong kemKeySize, byte *ciphertext, uint ciphertextLength, byte *decryptedAesKey);

	public static unsafe byte[] DecryptAesKey(byte[] ciphertext, byte[] privateKemKey) {
		byte[] aesKey = new byte[Cryptography.AesKeyLength];
		bool isSuccessful;
		
		fixed (byte *ciphertextPointer = ciphertext)
			fixed (byte *kemKeyPointer = privateKemKey)
				fixed (byte *aesKeyPointer = aesKey)
					isSuccessful = decrypt_aes_key_with_ml_kem(kemKeyPointer, (ulong) privateKemKey.LongLength, ciphertextPointer, (uint) ciphertext.Length, aesKeyPointer) != 0;
		
		return !isSuccessful ? throw new Exception("Could not decrypt AES key") : aesKey;
	}
}