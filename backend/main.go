package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/time/rate"
)

// Configuration
type Config struct {
	Port           string
	DatabaseURL    string
	AllowedOrigins []string
	RateLimit      int
	MaxEvents      int
	RetentionDays  int
	LogLevel       string
	TLSCertFile    string
	TLSKeyFile     string
}

// Event represents an analytics event
type Event struct {
	ID        int       `json:"id" db:"id"`
	Domain    string    `json:"domain" db:"domain"`
	Path      string    `json:"path" db:"path"`
	Referrer  string    `json:"referrer" db:"referrer"`
	UserAgent string    `json:"ua" db:"user_agent"`
	IP        string    `json:"ip" db:"ip_address"`
	Time      time.Time `json:"time" db:"created_at"`
}

// HealthStatus represents the health check response
type HealthStatus struct {
	Status      string    `json:"status"`
	Timestamp   time.Time `json:"timestamp"`
	Version     string    `json:"version"`
	Uptime      string    `json:"uptime"`
	EventCount  int       `json:"event_count"`
	ClientCount int       `json:"client_count"`
}

// Server represents the analytics server
type Server struct {
	config      Config
	db          *sql.DB
	clients     map[*websocket.Conn]bool
	clientsMux  sync.RWMutex
	rateLimiter *RateLimiter
	upgrader    websocket.Upgrader
	startTime   time.Time
	version     string
}

// RateLimiter provides per-IP rate limiting
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// Input validation patterns
var (
	domainPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
	pathPattern   = regexp.MustCompile(`^[a-zA-Z0-9\-._~:/?#[\]@!$&'()*+,;=%]*$`)
)

func loadConfig() Config {
	return Config{
		Port:           getEnv("PORT", "8080"),
		DatabaseURL:    getEnv("DATABASE_URL", "analytics.db"),
		AllowedOrigins: strings.Split(getEnv("ALLOWED_ORIGINS", "*"), ","),
		RateLimit:      getEnvInt("RATE_LIMIT", 100),
		MaxEvents:      getEnvInt("MAX_EVENTS", 100000),
		RetentionDays:  getEnvInt("RETENTION_DAYS", 90),
		LogLevel:       getEnv("LOG_LEVEL", "INFO"),
		TLSCertFile:    getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:     getEnv("TLS_KEY_FILE", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func NewRateLimiter(rateLimit rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     rateLimit,
		burst:    burst,
	}
}

func (rl *RateLimiter) GetLimiter(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if limiter, exists := rl.limiters[ip]; exists {
		return limiter
	}

	limiter := rate.NewLimiter(rl.rate, rl.burst)
	rl.limiters[ip] = limiter
	return limiter
}

func (rl *RateLimiter) CleanupOldEntries() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, limiter := range rl.limiters {
		if limiter.Allow() {
			delete(rl.limiters, ip)
		}
	}
}

func NewServer() (*Server, error) {
	config := loadConfig()

	// Initialize database
	db, err := sql.Open("sqlite3", config.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Create events table
	if err := createTables(db); err != nil {
		return nil, fmt.Errorf("failed to create tables: %v", err)
	}

	server := &Server{
		config:      config,
		db:          db,
		clients:     make(map[*websocket.Conn]bool),
		rateLimiter: NewRateLimiter(rate.Limit(config.RateLimit), config.RateLimit*2),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if len(config.AllowedOrigins) == 1 && config.AllowedOrigins[0] == "*" {
					return true
				}
				for _, allowedOrigin := range config.AllowedOrigins {
					if origin == allowedOrigin {
						return true
					}
				}
				return false
			},
		},
		startTime: time.Now(),
		version:   "1.0.0",
	}

	// Start cleanup routines
	go server.cleanupOldEvents()
	go server.cleanupRateLimiters()

	return server, nil
}

func createTables(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT NOT NULL,
		path TEXT NOT NULL,
		referrer TEXT,
		user_agent TEXT,
		ip_address TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	
	CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
	CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);
	`

	_, err := db.Exec(query)
	return err
}

func (s *Server) cleanupOldEvents() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().AddDate(0, 0, -s.config.RetentionDays)
		_, err := s.db.Exec("DELETE FROM events WHERE created_at < ?", cutoff)
		if err != nil {
			log.Printf("Error cleaning up old events: %v", err)
		} else {
			log.Printf("Cleaned up events older than %d days", s.config.RetentionDays)
		}
	}
}

func (s *Server) cleanupRateLimiters() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.rateLimiter.CleanupOldEntries()
	}
}

func (s *Server) getClientIP(r *http.Request) string {
	// Check for X-Forwarded-For header (load balancer/proxy)
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check for X-Real-IP header
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// Use RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func (s *Server) validateAndSanitizeInput(domain, path string) (string, string, error) {
	// Validate and sanitize domain
	domain = strings.ToLower(strings.TrimSpace(domain))
	if len(domain) == 0 || len(domain) > 253 {
		return "", "", fmt.Errorf("invalid domain length")
	}
	if !domainPattern.MatchString(domain) {
		return "", "", fmt.Errorf("invalid domain format")
	}

	// Validate and sanitize path
	path = strings.TrimSpace(path)
	if len(path) == 0 {
		path = "/"
	}
	if len(path) > 2048 {
		return "", "", fmt.Errorf("path too long")
	}
	if !pathPattern.MatchString(path) {
		return "", "", fmt.Errorf("invalid path format")
	}

	// HTML escape for safety
	domain = html.EscapeString(domain)
	path = html.EscapeString(path)

	return domain, path, nil
}

func (s *Server) enableCORS(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")

	if len(s.config.AllowedOrigins) == 1 && s.config.AllowedOrigins[0] == "*" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	} else {
		for _, allowedOrigin := range s.config.AllowedOrigins {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
	}

	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return true
	}

	return false
}

func (s *Server) trackHandler(w http.ResponseWriter, r *http.Request) {
	// Handle CORS
	if s.enableCORS(w, r) {
		return
	}

	// Rate limiting
	clientIP := s.getClientIP(r)
	limiter := s.rateLimiter.GetLimiter(clientIP)
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		log.Printf("Rate limit exceeded for IP: %s", clientIP)
		return
	}

	// Only allow GET requests for tracking
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate and sanitize input
	domain, path, err := s.validateAndSanitizeInput(
		r.URL.Query().Get("domain"),
		r.URL.Query().Get("path"),
	)
	if err != nil {
		http.Error(w, "Invalid input: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Create event
	event := Event{
		Domain:    domain,
		Path:      path,
		Referrer:  html.EscapeString(r.Referer()),
		UserAgent: html.EscapeString(r.UserAgent()),
		IP:        clientIP,
		Time:      time.Now(),
	}

	// Save to database
	result, err := s.db.Exec(
		"INSERT INTO events (domain, path, referrer, user_agent, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		event.Domain, event.Path, event.Referrer, event.UserAgent, event.IP, event.Time,
	)
	if err != nil {
		log.Printf("Error saving event: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get the generated ID
	id, err := result.LastInsertId()
	if err == nil {
		event.ID = int(id)
	}

	// Broadcast to WebSocket clients
	s.broadcastEvent(event)

	// Log the event (structured logging)
	log.Printf("Event tracked: domain=%s, path=%s, ip=%s", event.Domain, event.Path, clientIP)

	// Return success
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) wsHandler(w http.ResponseWriter, r *http.Request) {
	// Rate limiting for WebSocket connections
	clientIP := s.getClientIP(r)
	limiter := s.rateLimiter.GetLimiter(clientIP)
	if !limiter.Allow() {
		http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}
	defer conn.Close()

	s.clientsMux.Lock()
	s.clients[conn] = true
	clientCount := len(s.clients)
	s.clientsMux.Unlock()

	log.Printf("New WebSocket client connected from %s (total: %d)", clientIP, clientCount)

	// Send recent events to new client
	s.sendRecentEvents(conn)

	// Set connection limits
	conn.SetReadLimit(512)
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// Handle connection in separate goroutine
	go s.handleWebSocketConnection(conn, clientIP)

	// Ping ticker for keeping connection alive
	ticker := time.NewTicker(54 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("WebSocket ping failed for %s: %v", clientIP, err)
				return
			}
		}
	}
}

func (s *Server) handleWebSocketConnection(conn *websocket.Conn, clientIP string) {
	defer func() {
		s.clientsMux.Lock()
		delete(s.clients, conn)
		clientCount := len(s.clients)
		s.clientsMux.Unlock()

		log.Printf("WebSocket client disconnected from %s (remaining: %d)", clientIP, clientCount)
	}()

	for {
		// Read message (mainly for ping/pong)
		if _, _, err := conn.ReadMessage(); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error for %s: %v", clientIP, err)
			}
			break
		}
	}
}

func (s *Server) sendRecentEvents(conn *websocket.Conn) {
	rows, err := s.db.Query("SELECT id, domain, path, referrer, user_agent, ip_address, created_at FROM events ORDER BY created_at DESC LIMIT 50")
	if err != nil {
		log.Printf("Error querying recent events: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var event Event
		err := rows.Scan(&event.ID, &event.Domain, &event.Path, &event.Referrer, &event.UserAgent, &event.IP, &event.Time)
		if err != nil {
			log.Printf("Error scanning event: %v", err)
			continue
		}

		if err := conn.WriteJSON(event); err != nil {
			log.Printf("Error sending event to client: %v", err)
			break
		}
	}
}

func (s *Server) broadcastEvent(event Event) {
	s.clientsMux.RLock()
	defer s.clientsMux.RUnlock()

	for conn := range s.clients {
		if err := conn.WriteJSON(event); err != nil {
			log.Printf("Error broadcasting to client: %v", err)
			conn.Close()
			delete(s.clients, conn)
		}
	}
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	// Get event count
	var eventCount int
	err := s.db.QueryRow("SELECT COUNT(*) FROM events").Scan(&eventCount)
	if err != nil {
		log.Printf("Error getting event count: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Get client count
	s.clientsMux.RLock()
	clientCount := len(s.clients)
	s.clientsMux.RUnlock()

	health := HealthStatus{
		Status:      "healthy",
		Timestamp:   time.Now(),
		Version:     s.version,
		Uptime:      time.Since(s.startTime).String(),
		EventCount:  eventCount,
		ClientCount: clientCount,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(health)
}

func (s *Server) Close() error {
	// Close all WebSocket connections
	s.clientsMux.Lock()
	for conn := range s.clients {
		conn.Close()
	}
	s.clients = make(map[*websocket.Conn]bool)
	s.clientsMux.Unlock()

	// Close database
	return s.db.Close()
}

func main() {
	// Initialize server
	server, err := NewServer()
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}
	defer server.Close()

	// Setup routes
	mux := http.NewServeMux()
	mux.HandleFunc("/track", server.trackHandler)
	mux.HandleFunc("/ws", server.wsHandler)
	mux.HandleFunc("/health", server.healthHandler)
	mux.HandleFunc("/readiness", server.healthHandler)

	// Serve static files
	fs := http.FileServer(http.Dir("../frontend/"))
	mux.Handle("/", fs)

	// Create HTTP server with timeouts
	httpServer := &http.Server{
		Addr:         ":" + server.config.Port,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup graceful shutdown
	done := make(chan bool, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Server is shutting down...")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := httpServer.Shutdown(ctx); err != nil {
			log.Fatalf("Could not gracefully shutdown the server: %v", err)
		}
		close(done)
	}()

	// Start server
	log.Printf("🚀 Flowlytics Production Server v%s", server.version)
	log.Printf("📊 Dashboard: http://localhost:%s/dashboard.html", server.config.Port)
	log.Printf("📡 Tracking endpoint: http://localhost:%s/track", server.config.Port)
	log.Printf("🔌 WebSocket endpoint: ws://localhost:%s/ws", server.config.Port)
	log.Printf("❤️  Health check: http://localhost:%s/health", server.config.Port)
	log.Printf("📊 Database: %s", server.config.DatabaseURL)
	log.Printf("🛡️  Rate limit: %d req/min per IP", server.config.RateLimit)
	log.Printf("📈 Retention: %d days", server.config.RetentionDays)

	if server.config.TLSCertFile != "" && server.config.TLSKeyFile != "" {
		log.Printf("🔒 Starting HTTPS server on port %s", server.config.Port)
		if err := httpServer.ListenAndServeTLS(server.config.TLSCertFile, server.config.TLSKeyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not start HTTPS server: %v", err)
		}
	} else {
		log.Printf("🌐 Starting HTTP server on port %s", server.config.Port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Could not start HTTP server: %v", err)
		}
	}

	<-done
	log.Println("✅ Server stopped gracefully")
}
