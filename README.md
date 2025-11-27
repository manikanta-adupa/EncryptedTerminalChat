# tchat - Encrypted P2P Terminal Chat

A secure, end-to-end encrypted **peer-to-peer** chat application for your terminal. Built with Python using Diffie-Hellman key exchange and AES-256 encryption.

## Features

- 🔗 **True P2P Architecture** - No central server, connect directly to peers
- 🔐 **Diffie-Hellman Key Exchange** - Secure key agreement without sharing secrets
- 🔒 **AES-256 Encryption** - Military-grade encryption using Fernet
- 🌐 **Network Support** - Works over local networks (LAN)
- 💬 **Full-Duplex** - Send and receive messages simultaneously
- 🖥️ **Terminal-Based** - No GUI needed, works in any terminal
- 📝 **Connection Requests** - Accept or reject incoming connections

## Installation

```bash
git clone https://github.com/manikanta-adupa/EncryptedTerminalChat.git
cd echat
pip install -e .
```

## Usage

### Start echat

Both users run the same command:

```bash
echat
```

### What You'll See

```
==================================================
  echat - Encrypted P2P Terminal Chat
==================================================

  Your IP: 192.168.1.100
  Listening on port: 9999

  Share your IP with others to let them connect.
==================================================

Options:
  1. Connect to a peer (enter their IP)
  2. Wait for incoming connections
  3. Exit

Enter peer IP to connect, or press Enter to wait:
```

### Connecting to a Peer

**User A (initiator):**
```
Enter peer IP to connect, or press Enter to wait: 192.168.1.101
Connecting to 192.168.1.101:9999...
Waiting for peer to accept...
Connection accepted!
Establishing secure connection...
Secure connection established!
==================================================
  You can now chat securely. Type 'exit' to quit.
==================================================
```

**User B (receiver):**
```
==================================================
  Incoming connection from 192.168.1.100
==================================================
Accept connection? (y/n): y
Establishing secure connection...
Secure connection established!
==================================================
  You can now chat securely. Type 'exit' to quit.
==================================================
```

### Custom Port

```bash
echat -p 8888
```

## How It Works

```
┌─────────────┐                    ┌─────────────┐
│   User A    │                    │   User B    │
│             │                    │             │
│  Listening  │   Connection Req   │  Listening  │
│  on :9999   │◄───────────────────│  on :9999   │
│             │                    │             │
│             │   Accept? (y/n)    │             │
│             │──────────────────►│             │
│             │                    │             │
│             │   Key Exchange     │             │
│             │◄──────────────────►│             │
│             │                    │             │
│             │  Encrypted Chat    │             │
│             │◄══════════════════►│             │
└─────────────┘                    └─────────────┘
```

1. **Both users start echat** - Each listens for incoming connections
2. **One user connects** - Enters the other's IP address
3. **Accept/Reject** - Receiver chooses to accept or reject
4. **Key Exchange** - Diffie-Hellman establishes shared secret
5. **Secure Chat** - All messages encrypted with AES-256

## Security

- ✅ Private keys never leave each machine
- ✅ Shared secret computed independently on both sides
- ✅ All messages encrypted with AES-256
- ✅ Each session generates new keys
- ✅ No central server - direct peer connection

## Requirements

- Python 3.8+
- cryptography library

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
