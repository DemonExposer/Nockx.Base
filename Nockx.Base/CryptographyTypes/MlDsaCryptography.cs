using System.Runtime.InteropServices;

namespace Nockx.Base.CryptographyTypes;

internal static partial class MlDsaCryptography {
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte get_signature_size(byte *dsaPrivateKey, ulong keySize, byte *data, ulong dataSize, ulong *signatureSize);
	
	[LibraryImport("libnockx-base")]
	private static unsafe partial byte sign_with_ml_dsa(byte *dsaPrivateKey, ulong keySize, byte *data, ulong dataSize, byte *signature, ulong *signatureSize);

	public static unsafe byte[] Sign(byte[] data, byte[] privateDsaKey) {
		fixed (byte *dataPointer = data) {
			fixed (byte *privateDsaKeyPointer = privateDsaKey) {
				ulong signatureSize;
				if (get_signature_size(privateDsaKeyPointer, (ulong) privateDsaKey.LongLength, dataPointer, (ulong) data.LongLength, &signatureSize) == 0)
					throw new Exception("Could not get signature output size");

				byte[] signature = new byte[signatureSize];
				fixed (byte *signaturePointer = signature)
					if (sign_with_ml_dsa(privateDsaKeyPointer, (ulong) privateDsaKey.LongLength, dataPointer, (ulong) data.LongLength, signaturePointer, &signatureSize) == 0)
						throw new Exception("Could not sign data");

				return signature;
			}
		}
	}

	[LibraryImport("libnockx-base")]
	private static unsafe partial int verify_with_ml_dsa(byte *dsaPublicKey, int keySize, byte *data, ulong dataSize, byte *signature, uint signatureSize);

	public static unsafe bool Verify(byte[] data, byte[] signature, byte[] dsaPublicKey) {
		int result;
		
		fixed (byte *dataPointer = data)
		fixed (byte *signaturePointer = signature)
		fixed (byte *dsaPublicKeyPointer = dsaPublicKey)
			result = verify_with_ml_dsa(dsaPublicKeyPointer, dsaPublicKey.Length, dataPointer, (ulong) data.LongLength, signaturePointer, (uint) signature.Length);

		return result == -1 ? throw new Exception("Could not verify data") : result == 1;
	}
}