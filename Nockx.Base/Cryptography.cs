using System.Security.Cryptography;
using System.Text;
using Nockx.Base.ClassExtensions;
using Nockx.Base.CryptographyTypes;
using Nockx.Base.Util;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace Nockx.Base;

public static class Cryptography {
	public const string MlKem768 = "ML-KEM-768";
	public const string MlDsa65 = "ML-DSA-65";
	public const string Rsa = "RSA";
	
	public const int AesKeyLength = 32;
	public const int RsaKeyLength = 256;
	public const int KemEncapsulationLength = 1088;

	public static void GenerateCombinedKeyFile() {
		if (File.Exists("private_key.pem"))
			throw new InvalidOperationException("Private key file already exists");
		
		if (!GenerateKey(MlKem768) || !GenerateKey(MlDsa65))
			throw new Exception("Key generation failed"); 
		
		GenerateRsaKey("private_rsa_key.pem", "public_rsa_key.pem");

		File.AppendAllText("private_key.pem", File.ReadAllText($"{MlKem768.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		File.AppendAllText("private_key.pem", File.ReadAllText($"{MlDsa65.ToLowerInvariant()}_private_key.pem").Trim() + '\n');
		File.AppendAllText("private_key.pem", File.ReadAllText("private_rsa_key.pem"));
		
		File.Delete($"{MlKem768.ToLowerInvariant()}_private_key.pem");
		File.Delete($"{MlDsa65.ToLowerInvariant()}_private_key.pem");
		File.Delete("private_rsa_key.pem");
		File.Delete("public_rsa_key.pem");
	}
	
	public static bool GenerateKey(string keyType) => MlKemCryptography.GenerateKey(keyType);

	public static KeyPair ReadKeyFromFile(string fileName, string keyType) => MlKemCryptography.ReadKeyFromFile(fileName, keyType);
	
	public static byte[] ReadPublicKeyFromString(string input, string keyType) =>  MlKemCryptography.ReadPublicKeyFromString(input, keyType);
	
	public static byte[] EncryptAesKeyWithMlKem(byte[] aesKey, byte[] publicKemKey) => MlKemCryptography.EncryptAesKey(aesKey, publicKemKey);
	
	public static byte[] DecryptAesKeyWithMlKem(byte[] ciphertext, byte[] privateKemKey) => MlKemCryptography.DecryptAesKey(ciphertext, privateKemKey);
	
	public static byte[] GenerateAesKey() => AesCryptography.GenerateKey();
	
	public static byte[] EncryptWithAes(byte[] data, int inputLength, byte[] aesKey) => AesCryptography.Encrypt(data, inputLength, aesKey);
	
	public static byte[] DecryptWithAes(byte[] data, byte[] aesKey) => AesCryptography.Decrypt(data, aesKey);

	public static (RsaKeyParameters, RsaKeyParameters) GenerateRsaKey(string privateKeyFile = "private_key.pem", string publicKeyFile = "public_key.pem") => RsaCryptography.GenerateKey(privateKeyFile, publicKeyFile);
	
	public static byte[] EncryptAesKeyWithRsa(byte[] aesKey, RsaKeyParameters rsaPublicKey) => RsaCryptography.EncryptAesKey(aesKey, rsaPublicKey);
	
	public static byte[] DecryptAesKeyWithRsa(byte[] encryptedAesKey, RsaKeyParameters rsaPrivateKey) => RsaCryptography.DecryptAesKey(encryptedAesKey, rsaPrivateKey);
	
	public static string SignWithRsa(string text, RsaKeyParameters privateKey) => RsaCryptography.Sign(text, privateKey);

	public static bool VerifyWithRsa(string text, string signature, RsaKeyParameters? personalPublicKey, RsaKeyParameters? foreignPublicKey, bool isOwnMessage) => RsaCryptography.Verify(text, signature, personalPublicKey, foreignPublicKey, isOwnMessage);

	public static byte[] EncryptBytes(byte[] input, RsaKeyParameters foreignRsaPublicKey, byte[] foreignKemPublicKey) {
		byte[] aesKey = GenerateAesKey();

		byte[] cipherBytes = EncryptWithAes(input, input.Length, aesKey);
		byte[] encryptedAesKey = EncryptAesKeyWithMlKem(aesKey, foreignKemPublicKey);
		byte[] doubleEncryptedAesKey = EncryptAesKeyWithRsa(encryptedAesKey[..AesKeyLength], foreignRsaPublicKey);

		byte[] output = new byte[doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength + cipherBytes.Length];
		Buffer.BlockCopy(doubleEncryptedAesKey, 0, output, 0, doubleEncryptedAesKey.Length);
		Buffer.BlockCopy(encryptedAesKey, AesKeyLength, output, doubleEncryptedAesKey.Length, encryptedAesKey.Length - AesKeyLength);
		Buffer.BlockCopy(cipherBytes, 0, output, doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength, cipherBytes.Length);
		
		return output;
	}
	
	public static byte[] DecryptBytes(byte[] input, RsaKeyParameters rsaPrivateKey, byte[] kemPrivateKey) {
		byte[] doubleEncryptedAesKey = new byte[RsaKeyLength];
		byte[] encryptedAesKey = new byte[AesKeyLength + KemEncapsulationLength];
		byte[] cipherBytes = new byte[input.Length - doubleEncryptedAesKey.Length - KemEncapsulationLength];
		
		Buffer.BlockCopy(input, 0, doubleEncryptedAesKey, 0, doubleEncryptedAesKey.Length);
		Buffer.BlockCopy(input, doubleEncryptedAesKey.Length, encryptedAesKey, AesKeyLength, KemEncapsulationLength);
		Buffer.BlockCopy(input, doubleEncryptedAesKey.Length + encryptedAesKey.Length - AesKeyLength, cipherBytes, 0, cipherBytes.Length);

		byte[] singleDecryptedAesKey = DecryptAesKeyWithRsa(doubleEncryptedAesKey, rsaPrivateKey);
		Buffer.BlockCopy(singleDecryptedAesKey, 0, encryptedAesKey, 0, AesKeyLength);
		byte[] fullyDecryptedAesKey = DecryptAesKeyWithMlKem(encryptedAesKey, kemPrivateKey);
		byte[] plainBytes = DecryptWithAes(cipherBytes, fullyDecryptedAesKey);
		
		return plainBytes;
	}

	public static (RsaKeyParameters, RsaKeyParameters) ImportRsaKey(string file) {
		RsaKeyParameters privateKey;
		using (StreamReader reader = File.OpenText(file)) {
			PemReader pemReader = new (reader);
			privateKey = (RsaKeyParameters) ((AsymmetricCipherKeyPair) pemReader.ReadObject()).Private;
		}

		return (privateKey, new RsaKeyParameters(false, privateKey.Modulus, RsaCryptography.RsaKeyExponent));
	}
	
	public static string Md5Hash(string input) => MD5.HashData(Encoding.Default.GetBytes(input)).Aggregate(new StringBuilder(), (sb, cur) => sb.Append(cur.ToString("x2"))).ToString();
	
	// Here we get the more specific methods
	
	public static DecryptedMessage Decrypt(Message message, RsaKeyParameters privateKey, bool isOwnMessage) {
		// Decrypt the AES key using RSA
		byte[] aesKeyEncrypted = Convert.FromBase64String(isOwnMessage ? message.SenderEncryptedKey : message.ReceiverEncryptedKey);
		
		byte[] aesKey = DecryptAesKeyWithRsa(aesKeyEncrypted, privateKey);
		
		// Decrypt the message using AES
		byte[] plainBytes = DecryptWithAes(Convert.FromBase64String(message.Body), aesKey);

		string body = Encoding.UTF8.GetString(plainBytes, 0, plainBytes.Length);
		return new DecryptedMessage { Id = message.Id, Body = body, Sender = message.Sender.ToBase64String(), DisplayName = message.SenderDisplayName, Timestamp = message.Timestamp};
	}
	
	public static Message Encrypt(string inputText, RsaKeyParameters personalPublicKey, RsaKeyParameters foreignPublicKey, RsaKeyParameters privateKey, byte[]? aesKeyIn = null, byte[]? aesKeyOut = null) {
		if (aesKeyIn != null && aesKeyIn.Length != AesKeyLength)
			throw new ArgumentException($"{nameof(aesKeyIn)} has to be of length {AesKeyLength}", nameof(aesKeyIn));
		
		if (aesKeyOut != null && aesKeyOut.Length != AesKeyLength)
			throw new ArgumentException($"{nameof(aesKeyOut)} has to be of length {AesKeyLength}", nameof(aesKeyOut));
		
		// Encrypt using AES
		byte[] aesKey = aesKeyIn ?? GenerateAesKey();
		if (aesKeyOut != null)
			Buffer.BlockCopy(aesKey, 0, aesKeyOut, 0, AesKeyLength);

		byte[] plainBytes = Encoding.UTF8.GetBytes(inputText);
		byte[] cipherBytes = EncryptWithAes(plainBytes, plainBytes.Length, aesKey);
		
		// Encrypt the AES key using RSA
		byte[] personalEncryptedKey = EncryptAesKeyWithRsa(aesKey, personalPublicKey);
		
		byte[] foreignEncryptedKey = EncryptAesKeyWithRsa(aesKey, foreignPublicKey);

		long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
		return new Message {
			Body = Convert.ToBase64String(cipherBytes),
			SenderEncryptedKey = Convert.ToBase64String(personalEncryptedKey),
			ReceiverEncryptedKey = Convert.ToBase64String(foreignEncryptedKey),
			Timestamp = timestamp,
			Signature = RsaCryptography.Sign(inputText + Convert.ToBase64String(aesKey) + foreignPublicKey.ToBase64String() + timestamp, privateKey),
			Sender = personalPublicKey,
			SenderDisplayName = ""
		};
	}
}