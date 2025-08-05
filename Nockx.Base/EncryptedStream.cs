namespace Nockx.Base;

public class EncryptedStream : Stream {
	private readonly List<byte> _surplus = [];
	private readonly Stream _underlyingStream;
	private readonly bool _forEncryption;

	public EncryptedStream(Stream underlyingStream, byte[] aesKey, bool forEncryption) {
		_underlyingStream = underlyingStream;
		_underlyingStream.SetAesKey(aesKey);
		_forEncryption = forEncryption;
	}

	public override void Flush() {
		throw new NotImplementedException();
	}
		
	public override int Read(byte[] buffer, int offset, int count) {
		List<byte> encryptedBytes = new (_surplus);
		_surplus.Clear();
		while (encryptedBytes.Count < count && _underlyingStream.Position != _underlyingStream.Length)
			encryptedBytes.AddRange(_underlyingStream.ReadEncrypted(0, _underlyingStream.GetBlockSize()));

		int read = Math.Min(count, encryptedBytes.Count);
			
		_surplus.AddRange(encryptedBytes[read..]);

		Buffer.BlockCopy(encryptedBytes.ToArray(), 0, buffer, offset, read);
		return read;
	}
		
	public override long Seek(long offset, SeekOrigin origin) {
		throw new NotImplementedException();
	}
		
	public override void SetLength(long value) {
		throw new NotImplementedException();
	}
		
	public override void Write(byte[] buffer, int offset, int count) {
		throw new NotImplementedException();
	}
		
	public override bool CanRead { get; }
	public override bool CanSeek { get; }
	public override bool CanWrite { get; }
	public override long Length { get => _underlyingStream.GetOutputLength(_forEncryption); }
	public override long Position { get; set; }
}