# AI Creative Draft Generator

A security-hardened FastAPI application for AI-powered creative content generation with enterprise-grade authentication, encrypted file storage, team collaboration, and real-time video calling capabilities.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104%2B-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-12%2B-316192)

## Features

### 🎨 AI-Powered Content Generation
- **Script Generation**: GPT-5 powered Hollywood-style script generation
- **Image Generation**: Flux AI image generation with multiple art styles
- **Video Generation**: Kling AI video generation (text-to-video)
- **Voice Generation**: ElevenLabs text-to-speech integration
- **AI Assistant**: Google Gemini Pro 2.5 chat assistant

### 🔒 Enterprise Security
- **Multi-layer Middleware**: 7-layer defense-in-depth architecture
  - Rate limiting (SlowAPI)
  - Host header validation
  - CORS protection
  - CSRF protection (double-submit cookie pattern)
  - Security headers (CSP, HSTS, X-Frame-Options)
  - Input validation (XSS, SQLi, command injection prevention)
  - Security monitoring and audit logging
- **Authentication**: Argon2id password hashing, JWT sessions
- **Two-Factor Authentication**: TOTP-based MFA with double-layer AES-256-GCM encryption
- **End-to-End Encryption**: AES-256-GCM for files, messages, and sensitive data
- **IDOR Protection**: Resource ownership validation on all endpoints
- **User API Keys**: Double-encrypted storage for user-provided API keys

### 👥 Collaboration Features
- **Team Management**: Create teams, invite members, role-based access control
- **Encrypted Messaging**: Secure direct messaging between users
- **File Sharing**: Encrypted file storage with team collaboration
- **Version Control**: Idea versioning with change tracking
- **Real-time Notifications**: In-app notification system

### 🎥 Communication
- **Video Calling**: WebRTC video calls with DTLS-SRTP encryption
- **Screen Sharing**: Real-time collaboration features

### 📊 Project Management
- **Flowchart Designer**: Mermaid.js diagram generation and storage
- **Ideas Dashboard**: Manage scripts, images, videos, and voice files
- **Search & Filter**: Advanced content organization

## Tech Stack

**Backend:**
- FastAPI + Uvicorn with HTTPS/TLS
- PostgreSQL with connection pooling (psycopg2)
- Redis (optional, for persistent rate limiting)

**Security:**
- Argon2id password hashing
- JWT session management
- AES-256-GCM encryption
- TOTP two-factor authentication
- Multi-layer middleware stack

**AI Integration:**
- OpenAI GPT-4/GPT-5 (via aimlapi.com)
- Google Gemini Pro 2.5
- Anthropic Claude
- Flux AI (image generation)
- Kling AI (video generation)
- ElevenLabs (voice generation)

**Frontend:**
- Jinja2 templates
- Vanilla JavaScript (ES6+)
- No build process required

## Prerequisites

- **Python 3.8+** (Python 3.10+ recommended)
- **PostgreSQL 12+** (PostgreSQL 14+ recommended)
- **Redis** (optional, for persistent rate limiting)
- **OpenSSL** (for SSL certificate generation)

### API Keys Required

To use AI features, you'll need API keys from:
- [Google AI Studio](https://aistudio.google.com/app/apikey) - For Gemini AI assistant
- [AIML API](https://aimlapi.com/) - For GPT-5, image, video, and voice generation (pay-as-you-go, $20 recommended)

Users provide their own API keys through the settings interface (stored with double-encryption).

## Installation

### Quick Install (Automated)

```bash
# Clone the repository
git clone <repository-url>
cd Gensis

# Run the installation script
chmod +x install.sh
./install.sh
```

The installation script will:
1. ✅ Verify PostgreSQL and Python are installed
2. ✅ Create `.env` from `.env.example`
3. ✅ Create PostgreSQL database and user
4. ✅ Set up Python virtual environment
5. ✅ Install dependencies
6. ✅ Create database tables
7. ✅ Generate SSL certificates
8. ✅ Check Redis status (optional)

### Manual Installation

#### 1. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install postgresql postgresql-contrib python3 python3-pip python3-venv openssl
```

**macOS:**
```bash
brew install postgresql python openssl
```

**Optional - Redis (for persistent rate limiting):**
```bash
# Ubuntu/Debian
sudo apt-get install redis-server

# macOS
brew install redis
```

#### 2. Set Up PostgreSQL

```bash
# Create PostgreSQL user
sudo -u postgres psql
CREATE USER secure_user WITH PASSWORD 'your_secure_password';
ALTER USER secure_user WITH CREATEDB LOGIN;
\q

# Create database
sudo -u postgres createdb -O secure_user creative_ai_db
```

#### 3. Clone and Configure

```bash
# Clone repository
git clone <repository-url>
cd Gensis

# Create and configure .env
cp .env.example .env
nano .env  # Update database credentials and other settings
```

**Important `.env` settings:**
```bash
# Database (Required)
DB_NAME=creative_ai_db
DB_USER=secure_user
DB_PASSWORD=your_secure_password
DB_HOST=localhost
DB_PORT=5432

# Security Keys (Auto-generated on first run if using dev placeholders)
SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_here
SESSION_SECRET=your_session_secret_here
CSRF_SECRET=your_csrf_secret_here
MASTER_ENCRYPTION_KEY=base64_encoded_32_byte_key_here

# Rate Limiting (Optional - uses memory by default)
REDIS_URL=memory://
# REDIS_URL=redis://localhost:6379/0  # Uncomment to use Redis

# SMTP Email (Optional - for email verification and notifications)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password
SMTP_FROM=your_email@gmail.com

# SSL/TLS
SSL_CERT_FILE=certs/server.crt
SSL_KEY_FILE=certs/server.key

# Environment
ENV=development
DEBUG=True
```

#### 4. Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

#### 5. Set Up Database

```bash
# Create all tables and admin user
python create_db.py
```

You'll be prompted to:
- Choose auto-generated secure password or enter your own
- Provide admin email, username, and optional first/last name
- The admin credentials will be displayed once - **save them securely!**

#### 6. Generate SSL Certificates

**Development (Self-signed):**
```bash
mkdir -p certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

**Production:**
Use proper SSL certificates from Let's Encrypt or a commercial CA.

## Running the Application

### Start the Server

```bash
# Activate virtual environment
source venv/bin/activate

# Start PostgreSQL (if not already running)
sudo systemctl start postgresql  # Linux
brew services start postgresql   # macOS

# Optional: Start Redis for persistent rate limiting
sudo systemctl start redis-server  # Linux
brew services start redis          # macOS

# Run the application
python main.py
```

The server will start on **https://localhost:8000**

### First Login

1. Navigate to https://localhost:8000
2. Click "Login"
3. Use the admin credentials from database setup
4. **Important**: On first login, you'll be prompted to enter your API keys:
   - **Gemini API Key**: Get from https://aistudio.google.com/app/apikey
   - **AIML API Key**: Get from https://aimlapi.com/ (pay-as-you-go, $20 recommended)
5. Your API keys are stored with double-encryption and never leave your database

### Access Points

- **Main Application**: https://localhost:8000
- **API Documentation**: https://localhost:8000/docs (development only)
- **Alternative API Docs**: https://localhost:8000/redoc (development only)

## Database Management

### Reset Database (Start Fresh)

```bash
# WARNING: This will delete all data!
python create_db.py
```

The script will:
1. Ask for confirmation before dropping tables
2. Recreate all tables with the latest schema
3. Prompt you to create a new admin user

**Note:** The `create_db.py` script always contains the latest database schema. If you need to update your database structure, simply run this script again (it will ask for confirmation before dropping existing tables).

## Project Structure

```
Gensis/
├── main.py                 # FastAPI application entry point
├── create_db.py           # Database setup script (latest schema)
├── install.sh             # Automated installation script
├── requirements.txt       # Python dependencies
├── .env.example          # Environment variables template
├── routers/              # API route handlers
│   ├── auth.py          # Authentication endpoints
│   ├── user.py          # User settings and API keys
│   ├── ideas.py         # Script/image/video/voice generation
│   ├── gemini.py        # Gemini AI assistant
│   ├── teams.py         # Team collaboration
│   ├── drive.py         # File storage
│   ├── messages.py      # Messaging
│   └── ...
├── utils/               # Utility modules
│   ├── encryption.py    # AES-256-GCM encryption
│   ├── api_key_crypto.py # Double-encrypted API key storage
│   ├── gpt5_service.py  # GPT-5 integration
│   ├── gemini_service.py # Gemini integration
│   ├── flux_service.py  # Image generation
│   ├── kling_service.py # Video generation
│   ├── voice_service.py # Voice generation
│   ├── auth_dependencies.py # Authentication middleware
│   └── ...
├── middleware/          # Security middleware
│   └── security.py     # Multi-layer security stack
├── templates/          # Jinja2 HTML templates
├── static/            # CSS, JavaScript, images
├── database/          # Database utilities
│   ├── connection.py  # Connection pooling
│   └── models.py      # SQLAlchemy models
└── certs/            # SSL certificates
```

## Security Features

### Defense in Depth (7 Layers)

1. **Rate Limiting**: Prevents brute force attacks
2. **Host Header Validation**: Prevents host header injection
3. **CORS**: Restrictive origin policy
4. **CSRF Protection**: Double-submit cookie pattern
5. **Security Headers**: CSP, HSTS, X-Frame-Options, X-Content-Type-Options
6. **Input Validation**: XSS, SQLi, command injection prevention
7. **Security Monitoring**: Audit logging and incident tracking

### Authentication & Authorization

- **Password Security**: Argon2id (time_cost=3, memory_cost=65536)
- **Session Management**: Secure, HttpOnly, SameSite=Strict cookies
- **Two-Factor Authentication**: TOTP with double-encrypted secrets
- **API Key Storage**: Double-layer AES-256-GCM encryption
- **IDOR Protection**: Ownership validation on all resources

### Data Encryption

- **End-to-End Encryption**: All sensitive data encrypted at rest
- **Per-User Encryption Keys**: HKDF-derived from master key + user ID
- **File Encryption**: AES-256-GCM for all uploaded files
- **API Keys**: Double-encrypted (random key encrypts API key, user key encrypts random key)

## Development

### Run in Development Mode

```bash
# Activate virtual environment
source venv/bin/activate

# Set development environment
export ENV=development
export DEBUG=True

# Run with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000 \
  --ssl-keyfile=certs/server.key --ssl-certfile=certs/server.crt
```

### Run Tests

```bash
pytest
pytest tests/test_auth.py  # Run specific test file
```

### Code Quality

```bash
# Format code
black .

# Lint code
flake8

# Type checking
mypy .
```

## Production Deployment

### Important Changes for Production

1. **Update `.env`:**
```bash
ENV=production
DEBUG=False
SESSION_COOKIE_SECURE=True
```

2. **Use Real SSL Certificates:**
   - Let's Encrypt (recommended for free SSL)
   - Commercial SSL provider

3. **Set Strong Secrets:**
   - Replace all dev placeholders with cryptographically random values
   - Generate with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

4. **Configure Redis:**
```bash
REDIS_URL=redis://localhost:6379/0
```

5. **Set Allowed Hosts:**
```bash
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

6. **Database Security:**
   - Use strong PostgreSQL password
   - Restrict database access to localhost or private network
   - Enable PostgreSQL SSL connections

7. **Reverse Proxy (Recommended):**
   - Use Nginx or Apache as reverse proxy
   - Handle SSL termination at proxy level
   - Add additional security headers

### Systemd Service (Linux)

Create `/etc/systemd/system/creative-ai.service`:

```ini
[Unit]
Description=AI Creative Draft Generator
After=network.target postgresql.service

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/Gensis
Environment="PATH=/path/to/Gensis/venv/bin"
ExecStart=/path/to/Gensis/venv/bin/python main.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable creative-ai
sudo systemctl start creative-ai
sudo systemctl status creative-ai
```

## Troubleshooting

### Database Connection Issues

```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Verify database exists
psql -U postgres -l | grep creative_ai_db

# Test connection with credentials
psql -U secure_user -d creative_ai_db -h localhost
```

### SSL Certificate Issues

**Development:**
```bash
# Regenerate self-signed certificates
rm -rf certs/
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

### Rate Limiting Issues

If using memory backend, limits reset on restart. Install Redis for persistence:

```bash
# Install Redis
sudo apt-get install redis-server  # Ubuntu/Debian
brew install redis                  # macOS

# Update .env
REDIS_URL=redis://localhost:6379/0
```

### API Key Issues

If AI features aren't working:
1. Go to Settings → API Keys
2. Verify both Gemini and AIML API keys are configured
3. Check API key validity at provider websites
4. Check server logs for API errors

### Database Schema Issues

If you see "column does not exist" or "table does not exist" errors:

```bash
# Recreate database with latest schema
python create_db.py
```

**WARNING:** This will drop all existing data. The script will ask for confirmation before proceeding.

## API Documentation

When running in development mode, API documentation is available at:

- **Swagger UI**: https://localhost:8000/docs
- **ReDoc**: https://localhost:8000/redoc

Key endpoints:

- `POST /api/v1/auth/register` - User registration
- `POST /api/v1/auth/login` - User login
- `POST /api/v1/ideas/generate-script` - Generate script with GPT-5
- `POST /api/v1/ideas/generate-image` - Generate image with Flux AI
- `POST /api/v1/ideas/generate-video` - Generate video with Kling AI
- `POST /api/v1/ideas/generate-voice` - Generate voice with ElevenLabs
- `POST /api/v1/gemini/chat` - Chat with Gemini AI assistant
- `GET /api/v1/ideas/my-ideas` - Get user's ideas and content
- `POST /api/v1/user/settings/api-keys` - Save user API keys

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new features
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues, questions, or feature requests, please:
- Open an issue on GitHub
- Check the troubleshooting section above
- Review the inline documentation in `CLAUDE.md`

## Acknowledgments

- **FastAPI** - Modern Python web framework
- **PostgreSQL** - Robust database system
- **SlowAPI** - Rate limiting for FastAPI
- **OpenAI** - GPT models
- **Google** - Gemini AI
- **AIML API** - Unified AI API platform
- **Anthropic** - Claude AI models

---

**Made with ❤️ for creative professionals**
