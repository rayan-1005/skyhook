# 🪝 Skyhook

> A secure, zero-config CLI file server with upload capabilities and encrypted transport

Skyhook is a modern replacement for `python -m http.server` with authentication, HTTPS support, and file upload capabilities. Perfect for quickly sharing files between machines or within a local network.

## ✨ Features

- **🔐 Secure by Default**: Optional HTTP Basic Auth and self-signed SSL certificates
- **📤 Upload Support**: Drag-and-drop file uploads via web interface
- **⚡ Fast**: Launch a server in any directory in under 1 second
- **🎨 Modern UI**: Beautiful, responsive web interface that works on mobile
- **🔍 Search & Filter**: Quickly find files in large directories
- **🛡️ Security Hardened**: Path sanitization prevents directory traversal attacks
- **📱 Mobile Friendly**: Upload files from your phone's browser

## 🚀 Quick Start

### Installation

```bash
pip install skyhook-rayan
```

Or install from source:

```bash
git clone https://github.com/rayan-1005/skyhook.git
cd skyhook
pip install -e .
```

### Basic Usage

```bash
# Serve current directory on port 8000
skyhook

# Serve a specific directory
skyhook /path/to/files

# Custom port
skyhook --port 8080

# Enable authentication
skyhook --auth username:password

# Enable HTTPS with self-signed certificate
skyhook --ssl

# Full configuration
skyhook /data --port 8443 --auth admin:secret --ssl
```

## 📖 Usage Examples

### Simple File Sharing

Share files in the current directory:

```bash
skyhook
```

Then visit `http://localhost:8000` in your browser.

### Secure File Transfer

Enable authentication and HTTPS for secure transfers:

```bash
skyhook --auth myuser:mypass --ssl
```

Access via `https://localhost:8000` (you'll need to accept the self-signed certificate warning).

### Remote Access

Bind to all interfaces to allow remote connections:

```bash
skyhook --host 0.0.0.0 --port 8000 --auth user:pass
```

Now accessible from other devices on your network at `http://YOUR_IP:8000`.

### Quick File Upload

Upload files to a specific directory:

```bash
cd /tmp/uploads
skyhook --auth upload:secret
```

Open the URL in your browser and drag files to upload.

## 🎯 Use Cases

- **Dev Workflow**: Quickly share build artifacts between machines
- **Network Transfers**: Move files between computers without USB drives
- **Mobile Uploads**: Upload photos from your phone to your computer
- **Team Collaboration**: Share files within a local network
- **Remote Work**: Securely transfer files to/from a remote server

## 🔒 Security Features

### Authentication

HTTP Basic Authentication protects your files from unauthorized access:

```bash
skyhook --auth username:password
```

Credentials are checked using constant-time comparison to prevent timing attacks.

### SSL/TLS Encryption

Enable HTTPS to encrypt all traffic:

```bash
skyhook --ssl
```

Skyhook automatically generates a self-signed certificate. For production use, configure a proper certificate with a reverse proxy like nginx.

### Path Sanitization

All file paths are strictly validated to prevent directory traversal attacks. Attempts to access files outside the served directory are blocked:

```
# These attacks are automatically prevented:
../../../etc/passwd  ❌ Blocked
../../secret.txt     ❌ Blocked
/etc/hosts           ❌ Blocked
```

## 🔧 CLI Reference

```
Usage: skyhook [PATH] [OPTIONS]

Arguments:
  PATH  Directory to serve [default: current directory]

Options:
  -p, --port INTEGER       Port to bind to [default: 8000]
  -h, --host TEXT          Host interface to bind to [default: 0.0.0.0]
  -a, --auth TEXT          Enable auth (format: username:password)
  --ssl                    Enable HTTPS with self-signed certificate
  --reload                 Enable auto-reload for development
  --help                   Show this message and exit

Commands:
  run    Start the file server (default command)
  version  Show Skyhook version
```

## 🌐 API Endpoints

Skyhook provides a RESTful API:

| Endpoint           | Method | Description             |
| ------------------ | ------ | ----------------------- |
| `/`                | GET    | List root directory     |
| `/browse/{path}`   | GET    | List specific directory |
| `/download/{path}` | GET    | Download a file         |
| `/upload`          | POST   | Upload files            |
| `/health`          | GET    | Health check            |

### Upload via curl

```bash
# Upload single file
curl -F "files=@myfile.txt" http://localhost:8000/upload

# Upload with authentication
curl -u username:password -F "files=@myfile.txt" http://localhost:8000/upload

# Upload multiple files
curl -F "files=@file1.txt" -F "files=@file2.txt" http://localhost:8000/upload

# Upload to subdirectory
curl -F "files=@myfile.txt" -F "path=subdir" http://localhost:8000/upload
```

## 🧪 Development

### Running Tests

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run security tests specifically
pytest tests/test_skyhook.py::TestSecurity -v
```

### Project Structure

```
skyhook/
├── src/
│   └── skyhook/
│       ├── __init__.py
│       ├── main.py          # CLI entrypoint
│       ├── server.py        # FastAPI application
│       ├── security.py      # Auth & SSL logic
│       └── templates/
│           └── index.html   # Web UI
├── tests/
│   └── test_skyhook.py      # Test suite
├── pyproject.toml           # Project metadata
└── README.md
```

## 📊 Performance

- **Memory footprint**: < 100MB during 1GB file transfers
- **Startup time**: < 1 second
- **Concurrent uploads**: Supported via async I/O
- **Large files**: Handled efficiently with chunked streaming

## 🗺️ Roadmap

### v1.1 (Planned)

- [ ] Support for `.zip` folder downloads
- [ ] Directory compression on-the-fly
- [ ] File preview for common formats

### v1.2 (Planned)

- [ ] Searchable file indexing for deep directories
- [ ] Advanced filtering (by date, size, type)
- [ ] Thumbnail generation for images

### v2.0 (Future)

- [ ] P2P mode using WebRTC (bypass firewalls)
- [ ] End-to-end encryption
- [ ] Multi-user support with permissions

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- Built with [FastAPI](https://fastapi.tiangolo.com/)
- Powered by [Uvicorn](https://www.uvicorn.org/)
- CLI built with [Typer](https://typer.tiangolo.com/)

## ⚠️ Security Notes

- Self-signed SSL certificates will trigger browser warnings (this is expected)
- For production use, configure proper SSL certificates via reverse proxy
- Always use authentication when exposing to untrusted networks
- Keep dependencies updated for security patches

## 📞 Support

- Issues: [GitHub Issues](https://github.com/rayan-1005/skyhook/issues)
- Documentation: [GitHub Wiki](https://github.com/rayan-1005/skyhook/wiki)

---

Made with ❤️ by the Rayan
