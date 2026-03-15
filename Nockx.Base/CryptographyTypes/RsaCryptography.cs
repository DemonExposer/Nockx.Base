using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace Nockx.Base.CryptographyTypes;

internal static class RsaCryptography {
	public static readonly BigInteger RsaKeyExponent = new ("10001", 16);
	
	public static (RsaKeyParameters, RsaKeyParameters) GenerateKey(string privateKeyFile, string publicKeyFile) {
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
	
	public static byte[] EncryptAesKey(byte[] aesKey, RsaKeyParameters rsaPublicKey) {
		OaepEncoding rsaEngine = new (new RsaEngine());
		rsaEngine.Init(true, rsaPublicKey);
		return rsaEngine.ProcessBlock(aesKey, 0, aesKey.Length);
	}
	
	public static byte[] DecryptAesKey(byte[] encryptedAesKey, RsaKeyParameters rsaPrivateKey) {
		OaepEncoding rsaEngine = new (new RsaEngine());
		rsaEngine.Init(false, rsaPrivateKey);
		return rsaEngine.ProcessBlock(encryptedAesKey, 0, encryptedAesKey.Length);
	}
	
	public static string Sign(string text, RsaKeyParameters privateKey) {
		byte[] bytes = Encoding.UTF8.GetBytes(text);
		RsaDigestSigner signer = new (new Sha256Digest());
		signer.Init(true, privateKey);
		
		signer.BlockUpdate(bytes, 0, bytes.Length);
		byte[] signature = signer.GenerateSignature();

		return Convert.ToBase64String(signature);
	}

	public static bool Verify(string text, string signature, RsaKeyParameters publicKey) {
		byte[] textBytes = Encoding.UTF8.GetBytes(text);
		byte[] signatureBytes = Convert.FromBase64String(signature);

		RsaDigestSigner verifier = new (new Sha256Digest());
		verifier.Init(false, publicKey);
		
		verifier.BlockUpdate(textBytes, 0, textBytes.Length);

		return verifier.VerifySignature(signatureBytes);
	}
}