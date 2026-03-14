using System.Runtime.CompilerServices;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nockx.Base;

public static class StreamExtensions {
	private class CipherPair {
		public required PaddedBufferedBlockCipher EncryptCipher;
		public required PaddedBufferedBlockCipher DecryptCipher;
	}
	
	private static readonly ConditionalWeakTable<Stream, CipherPair> StreamCiphers = [];
	
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
}