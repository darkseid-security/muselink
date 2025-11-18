#!/bin/bash
#
# AI Creative Generator - Installation Script
# This script sets up the application, database, and dependencies
#

set -e  # Exit on any error

echo "==========================================================="
echo "AI CREATIVE GENERATOR - INSTALLATION SCRIPT"
echo "==========================================================="
echo ""

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
    echo "❌ PostgreSQL is not installed. Please install PostgreSQL first."
    echo "   Ubuntu/Debian: sudo apt-get install postgresql postgresql-contrib"
    echo "   macOS: brew install postgresql"
    exit 1
fi

echo "✓ PostgreSQL is installed"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.8 or higher."
    exit 1
fi

echo "✓ Python 3 is installed ($(python3 --version))"

# Check if .env file exists
if [ ! -f .env ]; then
    echo ""
    echo "⚠️  .env file not found"
    if [ -f .env.example ]; then
        echo "Copying .env.example to .env..."
        cp .env.example .env
        echo "✓ Created .env file"
        echo ""
        echo "⚠️  IMPORTANT: Please edit .env and update the following:"
        echo "   - Database credentials (DB_USER, DB_PASSWORD)"
        echo "   - SMTP settings for email"
        echo "   - API keys (OpenAI, Anthropic, etc.)"
        echo ""
        read -p "Press Enter when you have configured .env..."
    else
        echo "❌ .env.example not found. Cannot proceed."
        exit 1
    fi
fi

echo ""
echo "==========================================================="
echo "STEP 1: Verifying PostgreSQL User"
echo "==========================================================="
echo ""

# Load database config from .env
export $(grep -v '^#' .env | grep -E '^(DB_NAME|DB_USER|DB_PASSWORD|DB_HOST|DB_PORT)=' | xargs)

DB_NAME=${DB_NAME:-creative_ai_db}
DB_USER=${DB_USER:-secure_user}
DB_HOST=${DB_HOST:-localhost}
DB_PORT=${DB_PORT:-5432}

# Check if PostgreSQL user exists
if ! psql -U postgres -h $DB_HOST -p $DB_PORT -tc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" 2>/dev/null | grep -q 1; then
    echo "❌ PostgreSQL user '$DB_USER' does not exist"
    echo ""
    echo "You need to create the PostgreSQL user first."
    echo "Run: ./setup_db_user.sh"
    echo ""
    echo "Or create manually:"
    echo "  psql -U postgres"
    echo "  CREATE USER $DB_USER WITH PASSWORD 'your_password';"
    echo "  ALTER USER $DB_USER WITH CREATEDB LOGIN;"
    echo ""
    exit 1
fi

echo "✓ PostgreSQL user '$DB_USER' exists"

echo ""
echo "==========================================================="
echo "STEP 2: Creating PostgreSQL Database"
echo "==========================================================="
echo ""

echo "Database: $DB_NAME"
echo "User: $DB_USER"
echo "Host: $DB_HOST:$DB_PORT"
echo ""

# Check if database already exists
if psql -U postgres -h $DB_HOST -p $DB_PORT -lqt | cut -d \| -f 1 | grep -qw $DB_NAME; then
    echo "⚠️  Database '$DB_NAME' already exists"
    read -p "Do you want to drop and recreate it? (yes/no): " -r
    echo
    if [[ $REPLY =~ ^[Yy]es$ ]]; then
        echo "Dropping database..."
        psql -U postgres -h $DB_HOST -p $DB_PORT -c "DROP DATABASE IF EXISTS $DB_NAME;"
        echo "Creating database..."
        psql -U postgres -h $DB_HOST -p $DB_PORT -c "CREATE DATABASE $DB_NAME OWNER $DB_USER ENCODING 'UTF8';"
        echo "✓ Database recreated"
    else
        echo "Keeping existing database"
    fi
else
    echo "Creating database..."
    psql -U postgres -h $DB_HOST -p $DB_PORT -c "CREATE DATABASE $DB_NAME OWNER $DB_USER ENCODING 'UTF8';"
    echo "✓ Database created"
fi

echo ""
echo "==========================================================="
echo "STEP 3: Setting Up Python Virtual Environment"
echo "==========================================================="
echo ""

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
else
    echo "✓ Virtual environment already exists"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

echo ""
echo "==========================================================="
echo "STEP 4: Installing Python Dependencies"
echo "==========================================================="
echo ""

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip --quiet

# Install requirements
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

echo "✓ Dependencies installed"

echo ""
echo "==========================================================="
echo "STEP 5: Creating Database Tables and Admin User"
echo "==========================================================="
echo ""

# Run database setup script
python3 create_db.py

echo ""
echo "==========================================================="
echo "STEP 6: Generating SSL Certificates (if needed)"
echo "==========================================================="
echo ""

# Check if SSL certificates exist
if [ ! -d "certs" ] || [ ! -f "certs/server.crt" ] || [ ! -f "certs/server.key" ]; then
    echo "SSL certificates not found. Generating self-signed certificates..."
    mkdir -p certs

    openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"

    echo "✓ Self-signed SSL certificates generated"
    echo "  Note: For production, use proper SSL certificates (Let's Encrypt, etc.)"
else
    echo "✓ SSL certificates already exist"
fi

echo ""
echo "==========================================================="
echo "STEP 7: Checking Redis (Optional)"
echo "==========================================================="
echo ""

# Check if Redis is installed
if command -v redis-server &> /dev/null; then
    echo "✓ Redis is installed"

    # Check if Redis is running
    if redis-cli ping &> /dev/null; then
        echo "✓ Redis is running"
        echo ""
        echo "💡 To use Redis for persistent rate limiting, update .env:"
        echo "   REDIS_URL=redis://localhost:6379/0"
    else
        echo "⚠️  Redis is installed but not running"
        echo ""
        echo "To start Redis:"
        echo "  Ubuntu/Debian: sudo systemctl start redis-server"
        echo "  macOS: brew services start redis"
        echo ""
        echo "Then update .env: REDIS_URL=redis://localhost:6379/0"
    fi
else
    echo "ℹ️  Redis is not installed (optional)"
    echo ""
    echo "The application will use in-memory rate limiting (REDIS_URL=memory://)"
    echo "This works fine but rate limits will reset on server restart."
    echo ""
    echo "To install Redis for persistent rate limiting:"
    echo "  Ubuntu/Debian: sudo apt-get install redis-server"
    echo "  macOS: brew install redis"
    echo ""
    echo "Then update .env: REDIS_URL=redis://localhost:6379/0"
fi

echo ""
echo "==========================================================="
echo "✓ INSTALLATION COMPLETE"
echo "==========================================================="
echo ""
echo "To start the application:"
echo "  1. Activate virtual environment: source venv/bin/activate"
echo "  2. Run the server: python main.py"
echo "  3. Access at: https://localhost:8000"
echo ""
echo "Default admin credentials were displayed during database setup."
echo "Make sure to save them securely!"
echo ""
echo "IMPORTANT NOTES:"
echo "  • PostgreSQL must be running"
echo "  • Redis is optional (using memory:// by default)"
echo "  • Configure your API keys in .env for AI features"
echo ""
echo "==========================================================="
