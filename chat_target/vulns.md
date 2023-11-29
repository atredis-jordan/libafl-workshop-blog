
A list of problems with the chat program
- the datalen can lie and get the client misaligned from the actual incoming messages
- The usrid is spoofable
- msg full of newline causes inf loop
- rename self to look like another user's id/nick
- null deref if rename from unknown user
- PING message leads to PONG message, but with buf overflow on sprintf size problems due to unexpected fmtstr stuff
- art message oob overflow stuff
- TODO more?