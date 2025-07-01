using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Nockx.Base;

public static class Cryptography {
	public const int AesKeyLength = 256;
	internal static readonly BigInteger RsaKeyExponent = new ("10001", 16);

	public static byte[] DecryptAesKey(byte[] encryptedAesKey, RsaKeyParameters rsaPrivateKey) {
    	OaepEncoding rsaEngine = new (new RsaEngine());
    	rsaEngine.Init(false, rsaPrivateKey);
    	return rsaEngine.ProcessBlock(encryptedAesKey, 0, encryptedAesKey.Length);
    }
	
	public static byte[] DecryptBytes(byte[] input, RsaKeyParameters privateKey) {
		byte[] encryptedAesKey = new byte[AesKeyLength];
		byte[] cipherBytes = new byte[input.Length - encryptedAesKey.Length];
		
		Buffer.BlockCopy(input, 0, encryptedAesKey, 0, encryptedAesKey.Length);
		Buffer.BlockCopy(input, encryptedAesKey.Length, cipherBytes, 0, cipherBytes.Length);

		byte[] aesKey = DecryptAesKey(encryptedAesKey, privateKey);
		(byte[] plainBytes, int length) = DecryptWithAes(cipherBytes, aesKey);
		
		return plainBytes[..length];
	}
	
	public static (byte[] plainBytes, int length) DecryptWithAes(byte[] data, byte[] aesKey) {
		AesEngine aesEngine = new ();
		PaddedBufferedBlockCipher cipher = new (new CbcBlockCipher(aesEngine), new Pkcs7Padding());
		cipher.Init(false, new KeyParameter(aesKey));
		
		byte[] plainBytes = new byte[cipher.GetOutputSize(data.Length)];
		int length = cipher.ProcessBytes(data, 0, data.Length, plainBytes, 0); // this should become a long so that files over 2GB can get encrypted too
		length += cipher.DoFinal(plainBytes, length);

		return (plainBytes, length);
	}

	public static byte[] EncryptAesKey(byte[] aesKey, RsaKeyParameters rsaPublicKey) {
		OaepEncoding rsaEngine = new (new RsaEngine());
		rsaEngine.Init(true, rsaPublicKey);
		return rsaEngine.ProcessBlock(aesKey, 0, aesKey.Length);
	}

	public static byte[] EncryptBytes(byte[] input, RsaKeyParameters foreignPublicKey) {
		byte[] aesKey = GenerateAesKey();

		byte[] cipherBytes = EncryptWithAes(input, input.Length, aesKey);
		byte[] encryptedAesKey = EncryptAesKey(aesKey, foreignPublicKey);

		byte[] output = new byte[encryptedAesKey.Length + cipherBytes.Length];
		Buffer.BlockCopy(encryptedAesKey, 0, output, 0, encryptedAesKey.Length);
		Buffer.BlockCopy(cipherBytes, 0, output, encryptedAesKey.Length, cipherBytes.Length);
		
		return output;
	}

	public static byte[] EncryptWithAes(byte[] data, int inputLength, byte[] aesKey) {
		AesEngine aesEngine = new ();
		PaddedBufferedBlockCipher cipher = new (new CbcBlockCipher(aesEngine), new Pkcs7Padding());
		cipher.Init(true, new KeyParameter(aesKey));
		
		byte[] cipherBytes = new byte[cipher.GetOutputSize(inputLength)];
		int length = cipher.ProcessBytes(data, 0, inputLength, cipherBytes, 0);
		length += cipher.DoFinal(cipherBytes, length);

		return cipherBytes;
	}
	
	public static byte[] GenerateAesKey() {
		CipherKeyGenerator aesKeyGen = new ();
		aesKeyGen.Init(new KeyGenerationParameters(new SecureRandom(), AesKeyLength));
		return aesKeyGen.GenerateKey();
	}

	public static (RsaKeyParameters, RsaKeyParameters) GenerateRsaKey(string privateKeyFile = "private_key.pem", string publicKeyFile = "public_key.pem") {
		RsaKeyPairGenerator rsaGenerator = new ();
		rsaGenerator.Init(new RsaKeyGenerationParameters(RsaKeyExponent, new SecureRandom(), 2048, 80));
			
		AsymmetricCipherKeyPair keyPair = rsaGenerator.GenerateKeyPair();

		RsaKeyParameters privateKey = (RsaKeyParameters) keyPair.Private;
		RsaKeyParameters publicKey = (RsaKeyParameters) keyPair.Public;
			
		// Write private and public keys to files
		using (TextWriter textWriter = new StreamWriter(privateKeyFile)) {
			PemWriter pemWriter = new (textWriter);
			pemWriter.WriteObject(privateKey);
			pemWriter.Writer.Flush();
		}

		using (TextWriter textWriter = new StreamWriter(publicKeyFile)) {
			PemWriter pemWriter = new (textWriter);
			pemWriter.WriteObject(publicKey);
			pemWriter.Writer.Flush();
		}
		
		return (privateKey, publicKey);
	}

	public static (RsaKeyParameters, RsaKeyParameters) ImportRsaKey(string file) {
		RsaKeyParameters privateKey;
		using (StreamReader reader = File.OpenText(file)) {
			PemReader pemReader = new (reader);
			privateKey = (RsaKeyParameters) ((AsymmetricCipherKeyPair) pemReader.ReadObject()).Private;
		}

		return (privateKey, new RsaKeyParameters(false, privateKey.Modulus, RsaKeyExponent));
	}
	
	public static string Md5Hash(string input) => MD5.HashData(Encoding.Default.GetBytes(input)).Aggregate(new StringBuilder(), (sb, cur) => sb.Append(cur.ToString("x2"))).ToString();
	
	public static string Sign(string text, RsaKeyParameters privateKey) {
		byte[] bytes = Encoding.UTF8.GetBytes(text);
		RsaDigestSigner signer = new (new Sha256Digest());
		signer.Init(true, privateKey);
		
		signer.BlockUpdate(bytes, 0, bytes.Length);
		byte[] signature = signer.GenerateSignature();

		return Convert.ToBase64String(signature);
	}

	public static bool Verify(string text, string signature, RsaKeyParameters? personalPublicKey, RsaKeyParameters? foreignPublicKey, bool isOwnMessage) {
		switch (isOwnMessage) {
			case true when personalPublicKey == null:
				throw new ArgumentNullException(nameof(personalPublicKey), "must not be null when verifying own messages");
			case false when foreignPublicKey == null:
				throw new ArgumentNullException(nameof(foreignPublicKey), "must not be null when verifying other's messages");
		}
		
		byte[] textBytes = Encoding.UTF8.GetBytes(text);
		byte[] signatureBytes = Convert.FromBase64String(signature);

		RsaDigestSigner verifier = new (new Sha256Digest());
		verifier.Init(false, isOwnMessage ? personalPublicKey : foreignPublicKey);
		
		verifier.BlockUpdate(textBytes, 0, textBytes.Length);

		return verifier.VerifySignature(signatureBytes);
	}
}