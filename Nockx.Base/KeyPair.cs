namespace Nockx.Base;

// TODO: add a constructor for this, forcing to check validity (in C++) on every creation of this object
public partial class KeyPair {
	public required string Type { get; init; }
	public required byte[] PublicKey { get; init; }
	public required byte[] PrivateKey { get; init; }
}