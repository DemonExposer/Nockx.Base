using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using Nockx.Base.ClassExtensions;
using Nockx.Base.Util;
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

	private class CipherPair {
		public required PaddedBufferedBlockCipher EncryptCipher;
		public required PaddedBufferedBlockCipher DecryptCipher;
	}
	
	private static readonly ConditionalWeakTable<Stream, CipherPair> StreamCiphers = [];
	
	// Extensions for Stream

	public static int GetBlockSize(this Stream stream) {
		if (!StreamCiphers.TryGetValue(stream, out CipherPair? cipherPair))
			throw new InvalidOperationException("Stream.SetAesKey has to be called before Stream.GetBlockSize");
		
		return cipherPair.EncryptCipher.GetBlockSize();
	}

	public static long GetOutputLength(this Stream stream, bool forEncryption) {
		if (!StreamCiphers.TryGetValue(stream, out CipherPair? cipherPair))
			throw new InvalidOperationException("Stream.SetAesKey has to be called before Stream.GetBlockSize");
		
		return forEncryption 
			? stream.Length - stream.Length % cipherPair.EncryptCipher.GetBlockSize() + cipherPair.EncryptCipher.GetBlockSize()
			: stream.Length + cipherPair.DecryptCipher.GetBlockSize() - 1 - (stream.Length + cipherPair.DecryptCipher.GetBlockSize() - 1) % cipherPair.DecryptCipher.GetBlockSize();
	}

	/*
	 * The choice to return a byte array instead of using a buffer was made because the output may be larger than the input.
	 * Since the aim of this library is to make encryption and decryption as simple as possible, while still maintaining control,
	 * the user shouldn't have to calculate output array sizes and slice them afterwards themselves, as is done in this method.
	 */
	public static byte[] ReadDecrypted(this Stream stream, int offset, int length) {
		long bytesLeft = stream.Length - stream.Position;
		bool isFinal = bytesLeft <= length;
    	
		if (!StreamCiphers.TryGetValue(stream, out CipherPair? cipherPair))
			throw new InvalidOperationException("Stream.SetAesKey has to be called before Stream.ReadDecrypted");
    	
		if (length % cipherPair.DecryptCipher.GetBlockSize() != 0)
			throw new ArgumentOutOfRangeException(nameof(length), $"{nameof(length)} must be a multiple of the cipher's block size ({cipherPair.DecryptCipher.GetBlockSize()})");
		
		byte[] buffer = new byte[length];
		int read = stream.Read(buffer, offset, length);

		if (read == 0)
			return [];

		byte[] plainBytes = new byte[isFinal ? cipherPair.DecryptCipher.GetOutputSize(read) : cipherPair.DecryptCipher.GetUpdateOutputSize(read)];
		int lengthDecrypted = cipherPair.DecryptCipher.ProcessBytes(buffer, 0, read, plainBytes, 0);
		if (isFinal)
			lengthDecrypted += cipherPair.DecryptCipher.DoFinal(plainBytes, lengthDecrypted);

		return plainBytes[..lengthDecrypted];
	}
	
	public static byte[] ReadEncrypted(this Stream stream, int offset, int length) {
    	bool isFinal = stream.Length - stream.Position <= length;
    	
    	if (!StreamCiphers.TryGetValue(stream, out CipherPair? cipherPair))
    		throw new InvalidOperationException("Stream.SetAesKey has to be called before Stream.ReadEncrypted");
    	
    	if (length % cipherPair.EncryptCipher.GetBlockSize() != 0 && !isFinal)
    		throw new ArgumentOutOfRangeException(nameof(length), $"If {nameof(length)} is less than the number of remaining bytes in the stream, it must be a multiple of the cipher's block size ({cipherPair.EncryptCipher.GetBlockSize()})");
    	
    	byte[] buffer = new byte[length];
    	int read = stream.Read(buffer, offset, length);

	    if (read == 0)
		    return [];

    	byte[] cipherBytes = new byte[isFinal ? cipherPair.EncryptCipher.GetOutputSize(read) : cipherPair.EncryptCipher.GetUpdateOutputSize(read)];
    	int lengthEncrypted = cipherPair.EncryptCipher.ProcessBytes(buffer, 0, read, cipherBytes, 0);
	    if (isFinal)
		    lengthEncrypted += cipherPair.EncryptCipher.DoFinal(cipherBytes, lengthEncrypted);

	    return cipherBytes[..lengthEncrypted];
    }
	
	public static void SetAesKey(this Stream stream, byte[] aesKey) {
		PaddedBufferedBlockCipher encryptCipher = new (new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
		encryptCipher.Init(true, new KeyParameter(aesKey));
		
		PaddedBufferedBlockCipher decryptCipher = new (new CbcBlockCipher(new AesEngine()), new Pkcs7Padding());
		decryptCipher.Init(false, new KeyParameter(aesKey));
		
		StreamCiphers.Add(stream, new  CipherPair { EncryptCipher = encryptCipher, DecryptCipher = decryptCipher });
	}
	
	// End of extensions for Stream
	
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
		int length = cipher.ProcessBytes(data, 0, data.Length, plainBytes, 0);
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
	
	// Here we get the more specific methods
	
	public static DecryptedMessage Decrypt(Message message, RsaKeyParameters privateKey, bool isOwnMessage) {
		// Decrypt the AES key using RSA
		byte[] aesKeyEncrypted = Convert.FromBase64String(isOwnMessage ? message.SenderEncryptedKey : message.ReceiverEncryptedKey);
		
		byte[] aesKey = DecryptAesKey(aesKeyEncrypted, privateKey);
		
		// Decrypt the message using AES
		(byte[] plainBytes, int length) = DecryptWithAes(Convert.FromBase64String(message.Body), aesKey);

		string body = Encoding.UTF8.GetString(plainBytes, 0, length);
		return new DecryptedMessage { Id = message.Id, Body = body, Sender = message.Sender.ToBase64String(), DisplayName = message.SenderDisplayName, Timestamp = message.Timestamp};
	}
	
	public static Message Encrypt(string inputText, RsaKeyParameters personalPublicKey, RsaKeyParameters foreignPublicKey, RsaKeyParameters privateKey, byte[]? aesKeyIn = null, byte[]? aesKeyOut = null) {
		if (aesKeyIn != null && aesKeyIn.Length != AesKeyLength / 8)
			throw new ArgumentException($"{nameof(aesKeyIn)} has to be of length {AesKeyLength / 8}", nameof(aesKeyIn));
		
		if (aesKeyOut != null && aesKeyOut.Length != AesKeyLength / 8)
			throw new ArgumentException($"{nameof(aesKeyOut)} has to be of length {AesKeyLength / 8}", nameof(aesKeyOut));
		
		// Encrypt using AES
		byte[] aesKey = aesKeyIn ?? GenerateAesKey();
		if (aesKeyOut != null)
			Buffer.BlockCopy(aesKey, 0, aesKeyOut, 0, AesKeyLength / 8);

		byte[] plainBytes = Encoding.UTF8.GetBytes(inputText);
		byte[] cipherBytes = EncryptWithAes(plainBytes, plainBytes.Length, aesKey);
		
		// Encrypt the AES key using RSA
		byte[] personalEncryptedKey = EncryptAesKey(aesKey, personalPublicKey);
		
		byte[] foreignEncryptedKey = EncryptAesKey(aesKey, foreignPublicKey);

		long timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
		return new Message {
			Body = Convert.ToBase64String(cipherBytes),
			SenderEncryptedKey = Convert.ToBase64String(personalEncryptedKey),
			ReceiverEncryptedKey = Convert.ToBase64String(foreignEncryptedKey),
			Timestamp = timestamp,
			Signature = Sign(inputText + timestamp, privateKey), // TODO: add receiver's key to this as well, so no forwarding can be done
			Sender = personalPublicKey,
			SenderDisplayName = ""
		};
	}
}