# Flowlytics Production Deployment Guide

## 🚀 Quick Start (Docker)

### Using Docker Compose (Recommended)
```bash
# Clone and setup
git clone <your-repo>
cd Flowlytics

# Create data directory
mkdir -p data

# Start the application
docker-compose up -d

# Check status
docker-compose logs -f
```

### Using Docker directly
```bash
# Build the image
cd backend
docker build -t flowlytics .

# Run the container
docker run -d \
  --name flowlytics \
  -p 8080:8080 \
  -v $(pwd)/data:/app/data \
  -e ALLOWED_ORIGINS=yourdomain.com \
  flowlytics
```

## 🏗️ Manual Deployment

### Prerequisites
- Go 1.21+
- SQLite3 development libraries
- SSL certificates (for production HTTPS)

### Build and Deploy
```bash
# Install dependencies
cd backend
go mod tidy

# Build for production
CGO_ENABLED=1 go build -o flowlytics

# Create configuration
cp ../.env.example .env
# Edit .env with your settings

# Create systemd service (Linux)
sudo cp deployment/flowlytics.service /etc/systemd/system/
sudo systemctl enable flowlytics
sudo systemctl start flowlytics
```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `DATABASE_URL` | `analytics.db` | Database connection string |
| `ALLOWED_ORIGINS` | `*` | Comma-separated allowed origins |
| `RATE_LIMIT` | `100` | Requests per minute per IP |
| `MAX_EVENTS` | `100000` | Maximum events in memory |
| `RETENTION_DAYS` | `90` | Days to keep events |
| `LOG_LEVEL` | `INFO` | Log level (DEBUG, INFO, WARN, ERROR) |
| `TLS_CERT_FILE` | | Path to TLS certificate |
| `TLS_KEY_FILE` | | Path to TLS private key |

### Security Configuration
```bash
# Production settings
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com
RATE_LIMIT=1000
TLS_CERT_FILE=/etc/ssl/certs/flowlytics.pem
TLS_KEY_FILE=/etc/ssl/private/flowlytics.key
```

## 🛡️ Production Security Checklist

- [ ] **HTTPS enabled** with valid SSL certificates
- [ ] **CORS configured** with specific allowed origins (not *)
- [ ] **Rate limiting** configured appropriately
- [ ] **Database secured** with proper permissions
- [ ] **Server hardened** (firewall, fail2ban, etc.)
- [ ] **Monitoring enabled** with health checks
- [ ] **Backups configured** for database
- [ ] **Log rotation** configured
- [ ] **Resource limits** set (memory, CPU)

## 📊 Monitoring

### Health Checks
```bash
# Basic health check
curl http://localhost:8080/health

# Response format
{
  "status": "healthy",
  "timestamp": "2024-12-16T...",
  "version": "1.0.0",
  "uptime": "2h34m12s",
  "event_count": 1234,
  "client_count": 5
}
```

### Prometheus Metrics (Future Enhancement)
Endpoint: `/metrics` (to be implemented)

## 🗄️ Database Management

### SQLite (Default)
- Automatic table creation
- Built-in data retention
- Suitable for small to medium traffic

### PostgreSQL (Enterprise)
```bash
# Environment setup
DATABASE_URL=postgres://user:password@localhost/flowlytics?sslmode=require

# Manual table creation
psql -d flowlytics -f deployment/schema.sql
```

## 🔄 Backup & Recovery

### Automated Backup Script
```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
sqlite3 /app/data/analytics.db ".backup /backups/analytics_${DATE}.db"
find /backups -name "analytics_*.db" -mtime +30 -delete
```

### Restore
```bash
# Stop service
systemctl stop flowlytics

# Restore database
cp /backups/analytics_20241216_120000.db /app/data/analytics.db

# Start service
systemctl start flowlytics
```

## 🚨 Troubleshooting

### Common Issues

1. **Database locked**
   ```bash
   # Check for zombie processes
   lsof /app/data/analytics.db
   ```

2. **Rate limit errors**
   ```bash
   # Increase rate limit
   RATE_LIMIT=1000
   ```

3. **Memory issues**
   ```bash
   # Reduce event retention
   RETENTION_DAYS=30
   MAX_EVENTS=50000
   ```

### Log Analysis
```bash
# Follow logs
journalctl -u flowlytics -f

# Check WebSocket connections
ss -tlnp | grep :8080
```

## 📈 Performance Tuning

### High Traffic Configuration
```bash
PORT=8080
DATABASE_URL=postgres://...
RATE_LIMIT=5000
MAX_EVENTS=1000000
RETENTION_DAYS=365
LOG_LEVEL=WARN
```

### Resource Limits (systemd)
```ini
[Service]
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=1G
CPUQuota=200%
```

## 🔒 SSL/TLS Setup

### Let's Encrypt (Certbot)
```bash
# Install certbot
sudo apt install certbot

# Get certificate
sudo certbot certonly --standalone -d analytics.yourdomain.com

# Update configuration
TLS_CERT_FILE=/etc/letsencrypt/live/analytics.yourdomain.com/fullchain.pem
TLS_KEY_FILE=/etc/letsencrypt/live/analytics.yourdomain.com/privkey.pem
```

## 🎯 Load Balancing

### Nginx Configuration
```nginx
upstream flowlytics {
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
}

server {
    listen 443 ssl http2;
    server_name analytics.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://flowlytics;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```