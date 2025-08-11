using System.Text.Json.Nodes;
using Nockx.Base.ClassExtensions;
using Org.BouncyCastle.Crypto.Parameters;

namespace Nockx.Base.Util;

public class Message {
	public long Id, ChatId, Timestamp;
	public string Body, ReceiverEncryptedKey, SenderEncryptedKey, Signature, SenderDisplayName;
	public RsaKeyParameters Sender;
	public bool IsRead;
	
	public static Message Parse(JsonObject jsonMessage) {
		Message message;
		try {
			message = new Message {
				Id = jsonMessage["id"]!.GetValue<long>(),
				ChatId = jsonMessage["chatId"]!.GetValue<long>(),
				Body = jsonMessage["text"]!.GetValue<string>(),
				ReceiverEncryptedKey = jsonMessage["receiverEncryptedKey"]!.GetValue<string>(),
				SenderEncryptedKey = jsonMessage["senderEncryptedKey"]?.GetValue<string>(),
				Timestamp = jsonMessage["timestamp"]!.GetValue<long>(),
				Signature = jsonMessage["signature"]!.GetValue<string>(),
				Sender = RsaKeyParametersExtension.FromBase64String(jsonMessage["sender"]!["key"]!.GetValue<string>()),
				SenderDisplayName = jsonMessage["sender"]!["displayName"]!.GetValue<string>(),
				IsRead = jsonMessage["isRead"]!.GetValue<bool>()
			};
		} catch (Exception e) { // TODO: make this better. currently this is just easy for identifying issues between client and server
			Console.WriteLine(e.Message);
			
			if (jsonMessage["id"] == null)
				Console.WriteLine("id null");
			if (jsonMessage["chatId"] == null)
				Console.WriteLine("chatId null");
			if (jsonMessage["text"] == null)
				Console.WriteLine("text null");
			if (jsonMessage["receiverEncryptedKey"] == null)
				Console.WriteLine("receiverEncryptedKey null");
			if (jsonMessage["senderEncryptedKey"] == null)
				Console.WriteLine("senderEncryptedKey null");
			if (jsonMessage["timestamp"] == null)
				Console.WriteLine("timestmap null");
			if (jsonMessage["signature"] == null)
				Console.WriteLine("signature null");
			if (jsonMessage["sender"] == null)
				Console.WriteLine("sender null");
			if (jsonMessage["isRead"] == null)
				Console.WriteLine("isRead null");
			
			message = new Message();
		}

		return message;
	}
}