# AI Creative Draft Generator

A security-hardened FastAPI application for AI-powered creative content generation with enterprise-grade authentication, encrypted file storage, team collaboration, and real-time video calling capabilities.

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

**⚠️ CRITICAL: `.env` Configuration Requirements** (App will crash if these are missing or incorrectly configured)

```bash
# ============================================
# DATABASE CONFIGURATION (REQUIRED)
# ============================================
# Must provide a strong password for the PostgreSQL database user
# The app will CRASH if the database connection fails
# Use a strong password with numbers, symbols, and uppercase letters

DB_NAME=creative_ai_db
DB_USER=secure_user
DB_PASSWORD=your_secure_password  # ⚠️ MUST MATCH the password you created above
DB_HOST=localhost
DB_PORT=5432

# Test your connection before starting the app:
# psql -U secure_user -d creative_ai_db -h localhost


# ============================================
# SMTP EMAIL CONFIGURATION (REQUIRED)
# ============================================
# Email verification and password reset will NOT work without this
# The app will NOT crash, but email features will fail silently
# Strongly recommended to configure, especially for production

SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password  # Use app-specific password, not your main password
SMTP_FROM=your_email@gmail.com

# Gmail App Password Instructions:
# 1. Enable 2-Factor Authentication on your Google Account
# 2. Go to https://myaccount.google.com/apppasswords
# 3. Select "Mail" and "Windows Computer" (or your device)
# 4. Copy the generated 16-character password into SMTP_PASSWORD
# 5. Remove spaces from the password

# Other SMTP Providers:
# - Outlook: smtp-mail.outlook.com:587
# - SendGrid: smtp.sendgrid.net:587
# - Mailgun: smtp.mailgun.org:587


# ============================================
# SECURITY KEYS (REQUIRED)
# ============================================
# Auto-generated on first run if using dev placeholders
# For production, generate with: python -c "import secrets; print(secrets.token_urlsafe(32))"

SECRET_KEY=your_secret_key_here
JWT_SECRET_KEY=your_jwt_secret_here
SESSION_SECRET=your_session_secret_here
CSRF_SECRET=your_csrf_secret_here
MASTER_ENCRYPTION_KEY=base64_encoded_32_byte_key_here


# ============================================
# CORS & ALLOWED HOSTS CONFIGURATION
# ============================================
# ⚠️ CRITICAL FOR SECURITY - Whitelist only trusted domains
# Misconfiguration exposes your app to CSRF and host header injection attacks
# Always specify exact domains in production - never use wildcards for production apps

# Development (Local testing only)
ALLOWED_HOSTS=localhost,127.0.0.1
CORS_ORIGINS=http://localhost:3000,http://localhost:8000,http://127.0.0.1:8000

# Production Examples:
# ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com
# CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com,https://app.yourdomain.com

# Never use these in production:
# - CORS_ORIGINS=*
# - ALLOWED_HOSTS=*


# ============================================
# RATE LIMITING (Optional)
# ============================================
# By default uses in-memory storage - limits reset on app restart
# For persistent rate limiting across restarts, configure Redis

REDIS_URL=memory://
# REDIS_URL=redis://localhost:6379/0  # Uncomment to use Redis


# ============================================
# SSL/TLS CONFIGURATION (REQUIRED)
# ============================================
SSL_CERT_FILE=certs/server.crt
SSL_KEY_FILE=certs/server.key


# ============================================
# ENVIRONMENT & DEBUG (REQUIRED)
# ============================================
# ⚠️ NEVER set DEBUG=True in production
# Set to 'production' for live deployments

ENV=development
DEBUG=True  # Change to False in production

# Production settings:
# ENV=production
# DEBUG=False
# SESSION_COOKIE_SECURE=True
```

**Environment-Specific Configuration Summary:**

| Setting | Development | Production |
|---------|-------------|-----------|
| `ENV` | `development` | `production` |
| `DEBUG` | `True` | `False` |
| `ALLOWED_HOSTS` | `localhost,127.0.0.1` | `yourdomain.com,www.yourdomain.com` |
| `CORS_ORIGINS` | `http://localhost:*` | `https://yourdomain.com,https://www.yourdomain.com` |
| `SESSION_COOKIE_SECURE` | `False` | `True` |
| `SSL_CERT_FILE` | Self-signed | Let's Encrypt / Commercial |

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

⚠️ **Important**: If you see database connection errors, verify your `.env` file has the correct `DB_PASSWORD` that matches your PostgreSQL user password.

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

### Pre-Flight Checklist

Before starting the application, verify all critical configurations:

```bash
# 1. Check PostgreSQL connection
psql -U secure_user -d creative_ai_db -h localhost

# 2. Verify .env file has all required settings
grep -E "^DB_|^SMTP_|^ALLOWED_HOSTS|^CORS_ORIGINS" .env

# 3. Confirm SSL certificates exist
ls -la certs/server.crt certs/server.key

# 4. Test SMTP configuration (optional but recommended)
# See Troubleshooting section for email testing commands
```

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

**If the app crashes immediately**, check these in order:
1. PostgreSQL is running and `DB_PASSWORD` is correct
2. SMTP settings are valid (or comment them out to skip email)
3. SSL certificates exist in `certs/` directory
4. All required `.env` variables are set

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
3. **CORS**: Restrictive origin policy (must whitelist domains)
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

2. **Configure ALLOWED_HOSTS (Critical Security)**
```bash
# ⚠️ Specify EXACT domains - never use wildcards or * in production
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com

# Example for multiple subdomains:
ALLOWED_HOSTS=example.com,www.example.com,api.example.com,admin.example.com,app.example.com
```

3. **Configure CORS_ORIGINS (Critical Security)**
```bash
# ⚠️ Only whitelist frontend domains that legitimately call this API
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com,https://app.yourdomain.com

# Common mistake - DON'T do this in production:
# CORS_ORIGINS=*  # Opens app to CSRF attacks!
# CORS_ORIGINS=http://*  # Still insecure
```

4. **Use Real SSL Certificates:**
   - Let's Encrypt (recommended for free SSL)
   - Commercial SSL provider

5. **Set Strong Secrets:**
   - Replace all dev placeholders with cryptographically random values
   - Generate with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`

6. **Configure Database:**
   - Use strong, randomly generated `DB_PASSWORD`
   - Restrict database access to localhost or private network only
   - Enable PostgreSQL SSL connections
   - Consider managed database service (AWS RDS, DigitalOcean, etc.)

7. **Configure SMTP (Email):**
```bash
# Use production email service
SMTP_SERVER=smtp.sendgrid.net
SMTP_PORT=587
SMTP_USERNAME=apikey
SMTP_PASSWORD=SG.your_sendgrid_api_key_here
SMTP_FROM=noreply@yourdomain.com
```

8. **Configure Redis:**
```bash
REDIS_URL=redis://secure_password@localhost:6379/0
```

9. **Reverse Proxy (Recommended):**
   - Use Nginx or Apache as reverse proxy
   - Handle SSL termination at proxy level
   - Add additional security headers
   - Hide backend application details

### Production Nginx Configuration Example

```nginx
upstream creative_ai {
    server 127.0.0.1:8000;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass https://creative_ai;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

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
EnvironmentFile=/path/to/Gensis/.env
ExecStart=/path/to/Gensis/venv/bin/python main.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

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

### Application Crashes on Startup

**Error: "could not connect to server"**
```
Check these in order:
1. PostgreSQL is running: sudo systemctl status postgresql
2. Database exists: psql -U postgres -l | grep creative_ai_db
3. DB_PASSWORD in .env matches PostgreSQL user password
4. DB_HOST and DB_PORT are correct
```

### Database Connection Issues

```bash
# Check PostgreSQL is running
pg_isready -h localhost -p 5432

# Verify database exists
psql -U postgres -l | grep creative_ai_db

# Test connection with credentials
psql -U secure_user -d creative_ai_db -h localhost

# If authentication fails, reset the password:
sudo -u postgres psql
ALTER USER secure_user WITH PASSWORD 'new_secure_password';
\q

# Update the new password in .env:
DB_PASSWORD=new_secure_password
```

### SMTP / Email Configuration Issues

**Test SMTP configuration:**
```python
python3 << 'EOF'
import smtplib
from email.mime.text import MIMEText

# Update these values from your .env file
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_email@gmail.com"
SMTP_PASSWORD = "your_app_password"
SMTP_FROM = "your_email@gmail.com"

try:
    server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
    server.starttls()
    server.login(SMTP_USERNAME, SMTP_PASSWORD)
    msg = MIMEText("Test email")
    msg['Subject'] = "Test"
    msg['From'] = SMTP_FROM
    msg['To'] = "test@example.com"
    server.send_message(msg)
    server.quit()
    print("✓ SMTP configuration is working!")
except Exception as e:
    print(f"✗ SMTP configuration failed: {e}")
EOF
```

**Common SMTP errors:**
- `"Username and password not accepted"` - Wrong SMTP_PASSWORD or app password not generated correctly
- `"SMTP server requires STARTTLS"` - Ensure SMTP_PORT is 587, not 25
- `"Could not connect to host"` - Check SMTP_SERVER is correct, firewall may be blocking

### SSL Certificate Issues

**Development:**
```bash
# Regenerate self-signed certificates
rm -rf certs/
mkdir certs
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

**Production (Let's Encrypt):**
```bash
# Install Certbot
sudo apt-get install certbot python3-certbot-nginx

# Get certificate
sudo certbot certonly --nginx -d yourdomain.com -d www.yourdomain.com

# Certificates will be in: /etc/letsencrypt/live/yourdomain.com/
```

### CORS and Host Header Issues

**Error: "CORS policy: No 'Access-Control-Allow-Origin' header"**
```
Solution: Update CORS_ORIGINS in .env to include your frontend domain
CORS_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
```

**Error: "Host header invalid"**
```
Solution: Update ALLOWED_HOSTS in .env to include your domain
ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com,api.yourdomain.com
```

### Rate Limiting Issues

If using memory backend, limits reset on restart. Install Redis for persistence:

```bash
# Install Redis
sudo apt-get install redis-server  # Ubuntu/Debian
brew install redis                  # macOS

# Update .env
REDIS_URL=redis://localhost:6379/0

# Test Redis connection:
redis-cli ping
# Should respond with: PONG
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
- Verify SMTP, database, CORS, and ALLOWED_HOSTS configuration before reporting issues

## Acknowledgments

- **FastAPI** - Modern Python web framework
- **PostgreSQL** - Robust database system
- **SlowAPI** - Rate limiting for FastAPI
- **OpenAI** - GPT models
- **Google** - Gemini AI
- **AIML API** - Unified AI API platform

**Note video calling function requires fixing due to crash
