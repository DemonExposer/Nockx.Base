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
		
	public override int Read(byte[] buffer, int offset, int count) => _forEncryption ? ReadEncrypted(buffer, offset, count) : ReadDecrypted(buffer, offset, count);

	private int ReadDecrypted(byte[] buffer, int offset, int count) {
		List<byte> decryptedBytes = new (_surplus);
		_surplus.Clear();
		while (decryptedBytes.Count < count && _underlyingStream.Position != _underlyingStream.Length) 
			decryptedBytes.AddRange(_underlyingStream.ReadDecrypted(0, _underlyingStream.GetBlockSize())); // TODO: figure out what to do with offset here
		
		int read = Math.Min(count, decryptedBytes.Count);
		Position += read;
		
		_surplus.AddRange(decryptedBytes[read..]);
		
		Buffer.BlockCopy(decryptedBytes.ToArray(), 0, buffer, offset, read);

		return read;
	}

	private int ReadEncrypted(byte[] buffer, int offset, int count) {
		List<byte> encryptedBytes = new (_surplus);
		_surplus.Clear();
		while (encryptedBytes.Count < count && _underlyingStream.Position != _underlyingStream.Length)
			encryptedBytes.AddRange(_underlyingStream.ReadEncrypted(0, _underlyingStream.GetBlockSize())); // TODO: offset again

		int read = Math.Min(count, encryptedBytes.Count);
		Position += read;
			
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
	
	public override bool CanRead => _underlyingStream.CanRead;
	public override bool CanSeek => false;
	public override bool CanWrite => false;
	public override long Length => _underlyingStream.GetOutputLength(_forEncryption);
	public override long Position { get; set; }
}