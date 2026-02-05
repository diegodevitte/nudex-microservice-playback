package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Configuration
type Config struct {
	Port          string
	RedisURL      string
	RabbitMQURL   string
	JWTSecret     string
	SigningSecret string
	TokenTTL      time.Duration
	RateLimit     int
}

// JWT Claims
type PlaybackClaims struct {
	VideoID   string `json:"video_id"`
	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
	jwt.RegisteredClaims
}

// Request models
type TokenRequest struct {
	VideoID string `json:"video_id" binding:"required"`
	UserID  string `json:"user_id"`
}

type PlaybackStartRequest struct {
	Token     string `json:"token" binding:"required"`
	UserAgent string `json:"user_agent"`
	IPAddress string `json:"ip_address"`
}

// Response models
type TokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	StreamURL string    `json:"stream_url"`
}

type ResolveResponse struct {
	VideoURL  string            `json:"video_url"`
	UserID    string            `json:"user_id"`
	VideoID   string            `json:"video_id"`
	SessionID string            `json:"session_id"`
	Metadata  map[string]string `json:"metadata"`
}

type AnalyticsEvent struct {
	Type      string            `json:"type"`
	Timestamp time.Time         `json:"timestamp"`
	VideoID   string            `json:"video_id"`
	UserID    string            `json:"user_id"`
	SessionID string            `json:"session_id"`
	Metadata  map[string]string `json:"metadata"`
}

// Global variables
var (
	cfg           Config
	redisClient   *redis.Client
	rabbitConn    *amqp.Connection
	rabbitChannel *amqp.Channel
)

func loadConfig() Config {
	return Config{
		Port:          getEnv("PORT", "8085"),
		RedisURL:      getEnv("REDIS_URL", "redis://localhost:6379"),
		RabbitMQURL:   getEnv("RABBITMQ_URL", "amqp://nudex_rabbit:nudex_rabbit_pass@localhost:5672/"),
		JWTSecret:     getEnv("JWT_SECRET", "nudex-playback-secret-2026"),
		SigningSecret: getEnv("SIGNING_SECRET", "nudex-signing-secret-2026"),
		TokenTTL:      time.Hour,        // 1 hour
		RateLimit:     100,              // tokens per minute
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Initialize Redis
func initRedis() {
	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}

	redisClient = redis.NewClient(opt)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	log.Println("✅ Connected to Redis")
}

// Initialize RabbitMQ
func initRabbitMQ() {
	var err error
	rabbitConn, err = amqp.Dial(cfg.RabbitMQURL)
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}

	rabbitChannel, err = rabbitConn.Channel()
	if err != nil {
		log.Fatalf("Failed to open RabbitMQ channel: %v", err)
	}

	// Declare queues
	_, err = rabbitChannel.QueueDeclare(
		"analytics.events", // queue name
		true,               // durable
		false,              // delete when unused
		false,              // exclusive
		false,              // no-wait
		nil,                // arguments
	)
	if err != nil {
		log.Fatalf("Failed to declare analytics queue: %v", err)
	}

	log.Println("✅ Connected to RabbitMQ")
}

// Rate limiting middleware
func rateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := context.Background()
		clientIP := c.ClientIP()
		key := fmt.Sprintf("rate_limit:playback:%s", clientIP)

		// Get current count
		count, err := redisClient.Get(ctx, key).Int()
		if err != nil && err != redis.Nil {
			c.JSON(500, gin.H{"error": "Rate limit check failed"})
			c.Abort()
			return
		}

		if count >= cfg.RateLimit {
			c.JSON(429, gin.H{"error": "Rate limit exceeded"})
			c.Abort()
			return
		}

		// Increment counter
		pipe := redisClient.Pipeline()
		pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, time.Minute)
		pipe.Exec(ctx)

		c.Next()
	}
}

// Health check
func healthCheck(c *gin.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	health := gin.H{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0.0",
	}

	// Check Redis
	if err := redisClient.Ping(ctx).Err(); err != nil {
		health["redis"] = "unhealthy"
		health["status"] = "degraded"
	} else {
		health["redis"] = "healthy"
	}

	// Check RabbitMQ
	if rabbitConn.IsClosed() {
		health["rabbitmq"] = "unhealthy"
		health["status"] = "degraded"
	} else {
		health["rabbitmq"] = "healthy"
	}

	c.JSON(200, health)
}

// Generate playback token
func generatePlaybackToken(c *gin.Context) {
	var req TokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	sessionID := uuid.New().String()
	
	// Create JWT claims
	claims := PlaybackClaims{
		VideoID:   req.VideoID,
		UserID:    req.UserID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(cfg.TokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   req.VideoID,
		},
	}

	// Generate token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}

	// Store token metadata in Redis
	ctx := context.Background()
	tokenKey := fmt.Sprintf("playback_token:%s", tokenString[:16]) // Use first 16 chars as key
	metadata := map[string]interface{}{
		"video_id":   req.VideoID,
		"user_id":    req.UserID,
		"session_id": sessionID,
		"created_at": time.Now().Unix(),
	}

	metadataJSON, _ := json.Marshal(metadata)
	err = redisClient.Set(ctx, tokenKey, metadataJSON, cfg.TokenTTL).Err()
	if err != nil {
		log.Printf("Failed to store token metadata: %v", err)
	}

	// Generate signed stream URL
	streamURL := generateSignedURL(req.VideoID, tokenString)

	// Send analytics event
	go sendAnalyticsEvent("playback_token_generated", AnalyticsEvent{
		Type:      "playback_token_generated",
		Timestamp: time.Now(),
		VideoID:   req.VideoID,
		UserID:    req.UserID,
		SessionID: sessionID,
		Metadata: map[string]string{
			"user_agent": c.GetHeader("User-Agent"),
			"ip_address": c.ClientIP(),
		},
	})

	c.JSON(200, TokenResponse{
		Token:     tokenString,
		ExpiresAt: time.Now().Add(cfg.TokenTTL),
		StreamURL: streamURL,
	})
}

// Resolve playback token
func resolvePlaybackToken(c *gin.Context) {
	tokenString := c.Param("token")
	if tokenString == "" {
		c.JSON(400, gin.H{"error": "Token is required"})
		return
	}

	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(tokenString, &PlaybackClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(cfg.JWTSecret), nil
	})

	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(*PlaybackClaims)
	if !ok || !token.Valid {
		c.JSON(401, gin.H{"error": "Invalid token claims"})
		return
	}

	// Check if token exists in Redis
	ctx := context.Background()
	tokenKey := fmt.Sprintf("playback_token:%s", tokenString[:16])
	exists, err := redisClient.Exists(ctx, tokenKey).Result()
	if err != nil || exists == 0 {
		c.JSON(401, gin.H{"error": "Token not found or expired"})
		return
	}

	// Generate actual video URL (this would typically fetch from catalog service)
	videoURL := generateVideoURL(claims.VideoID)

	c.JSON(200, ResolveResponse{
		VideoURL:  videoURL,
		UserID:    claims.UserID,
		VideoID:   claims.VideoID,
		SessionID: claims.SessionID,
		Metadata: map[string]string{
			"resolution": "1080p",
			"format":     "mp4",
		},
	})
}

// Start playback (analytics)
func startPlayback(c *gin.Context) {
	var req PlaybackStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	// Parse token to get session info
	token, err := jwt.ParseWithClaims(req.Token, &PlaybackClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(cfg.JWTSecret), nil
	})

	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid token"})
		return
	}

	claims, ok := token.Claims.(*PlaybackClaims)
	if !ok || !token.Valid {
		c.JSON(401, gin.H{"error": "Invalid token claims"})
		return
	}

	// Send playback start event
	go sendAnalyticsEvent("playback_started", AnalyticsEvent{
		Type:      "playback_started",
		Timestamp: time.Now(),
		VideoID:   claims.VideoID,
		UserID:    claims.UserID,
		SessionID: claims.SessionID,
		Metadata: map[string]string{
			"user_agent": req.UserAgent,
			"ip_address": req.IPAddress,
		},
	})

	c.JSON(200, gin.H{
		"message":    "Playback started",
		"session_id": claims.SessionID,
	})
}

// Generate signed URL for video access
func generateSignedURL(videoID, token string) string {
	baseURL := "https://cdn.nudex.com/videos"
	expires := strconv.FormatInt(time.Now().Add(cfg.TokenTTL).Unix(), 10)
	
	// Create signature
	message := fmt.Sprintf("%s/%s?expires=%s&token=%s", baseURL, videoID, expires, token)
	h := hmac.New(sha256.New, []byte(cfg.SigningSecret))
	h.Write([]byte(message))
	signature := hex.EncodeToString(h.Sum(nil))

	// Build final URL
	signedURL := fmt.Sprintf("%s/%s.mp4?expires=%s&token=%s&signature=%s", 
		baseURL, videoID, expires, url.QueryEscape(token), signature)

	return signedURL
}

// Generate video URL (mock implementation)
func generateVideoURL(videoID string) string {
	return fmt.Sprintf("https://cdn.nudex.com/videos/%s.mp4", videoID)
}

// Send analytics event to RabbitMQ
func sendAnalyticsEvent(eventType string, event AnalyticsEvent) {
	if rabbitChannel == nil {
		log.Printf("RabbitMQ not available, skipping event: %s", eventType)
		return
	}

	eventJSON, err := json.Marshal(event)
	if err != nil {
		log.Printf("Failed to marshal analytics event: %v", err)
		return
	}

	err = rabbitChannel.Publish(
		"",                 // exchange
		"analytics.events", // routing key
		false,              // mandatory
		false,              // immediate
		amqp.Publishing{
			ContentType: "application/json",
			Body:        eventJSON,
		},
	)

	if err != nil {
		log.Printf("Failed to send analytics event: %v", err)
	}
}

// Cleanup resources
func cleanup() {
	if rabbitChannel != nil {
		rabbitChannel.Close()
	}
	if rabbitConn != nil {
		rabbitConn.Close()
	}
	if redisClient != nil {
		redisClient.Close()
	}
}

func main() {
	cfg = loadConfig()

	// Initialize services
	initRedis()
	initRabbitMQ()
	defer cleanup()

	// Setup Gin
	if os.Getenv("GO_ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	// Middleware
	r.Use(rateLimitMiddleware())

	// Routes
	r.GET("/health", healthCheck)
	r.POST("/playback/token", generatePlaybackToken)
	r.GET("/playback/resolve/:token", resolvePlaybackToken)
	r.POST("/playback/start", startPlayback)

	log.Printf("🎬 NUDEX Playback Service starting on port %s", cfg.Port)
	log.Fatal(http.ListenAndServe(":"+cfg.Port, r))
}