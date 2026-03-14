using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Nockx.Base.CryptographyTypes;

internal static class AesCryptography {
	public static byte[] GenerateKey() {
		CipherKeyGenerator aesKeyGen = new ();
		aesKeyGen.Init(new KeyGenerationParameters(new SecureRandom(), Cryptography.AesKeyLength));
		return aesKeyGen.GenerateKey();
	}
	
	public static byte[] Encrypt(byte[] data, int inputLength, byte[] aesKey) {
		AesEngine aesEngine = new ();
		PaddedBufferedBlockCipher cipher = new (new CbcBlockCipher(aesEngine), new Pkcs7Padding());
		cipher.Init(true, new KeyParameter(aesKey));
		
		byte[] cipherBytes = new byte[cipher.GetOutputSize(inputLength)];
		int length = cipher.ProcessBytes(data, 0, inputLength, cipherBytes, 0);
		length += cipher.DoFinal(cipherBytes, length);

		return cipherBytes;
	}
	
	public static byte[] Decrypt(byte[] data, byte[] aesKey) {
		AesEngine aesEngine = new ();
		PaddedBufferedBlockCipher cipher = new (new CbcBlockCipher(aesEngine), new Pkcs7Padding());
		cipher.Init(false, new KeyParameter(aesKey));
		
		byte[] plainBytes = new byte[cipher.GetOutputSize(data.Length)];
		int length = cipher.ProcessBytes(data, 0, data.Length, plainBytes, 0);
		length += cipher.DoFinal(plainBytes, length);

		return plainBytes[..length];
	}
}