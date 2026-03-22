package internal

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ConnectionChallenge is sent to the client to initiate handshake.
type ConnectionChallenge struct {
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	ServerID  string `json:"server_id"`
}

// HandshakeResponse is the client's reply to a challenge.
type HandshakeResponse struct {
	Signature  string `json:"signature"`
	PlayerType string `json:"player_type"`
	SessionID  string `json:"session_id"`
	AuthToken  string `json:"auth_token"`
	SDKVersion string `json:"sdk_version"`
}

// AuthenticatedConnection holds per-connection state after a completed handshake.
type AuthenticatedConnection struct {
	ConnID     string
	PlayerID   string
	PlayerType string
	SessionID  string
	HMACKey    []byte
	LastSeq    uint64
}

// SignedMessage wraps a payload with sequence and HMAC signature.
type SignedMessage struct {
	Seq       uint64 `json:"seq"`
	Payload   []byte `json:"payload"`
	Signature string `json:"signature"`
}

// ProtocolEnforcer manages HMAC handshakes and validates signed messages.
type ProtocolEnforcer struct {
	connections map[string]*AuthenticatedConnection
	challenges  map[string]*ConnectionChallenge
	sdkSecret   []byte
	serverID    string
	mu          sync.RWMutex

	// connToPlayer and playerToConn provide bidirectional lookup.
	connToPlayer sync.Map
	playerToConn sync.Map

	// OnAuthenticated is called after successful handshake, before the
	// handshake_ok message is sent. Useful for joining rooms synchronously.
	OnAuthenticated func(connID, playerType, sessionID, playerID string)

	// OnDisconnect is called when a connection is removed.
	OnDisconnect func(connID, playerID string)

	// SendFunc delivers a message to a connection. Must be set by the host.
	SendFunc func(connID string, msg []byte) bool
}

// NewProtocolEnforcer creates a ProtocolEnforcer with the given shared SDK secret.
func NewProtocolEnforcer(sdkSecret []byte, serverID string) *ProtocolEnforcer {
	if serverID == "" {
		serverID = "ws-auth-server"
	}
	return &ProtocolEnforcer{
		connections: make(map[string]*AuthenticatedConnection),
		challenges:  make(map[string]*ConnectionChallenge),
		sdkSecret:   sdkSecret,
		serverID:    serverID,
	}
}

// HandleConnect generates a challenge for a new connection and sends it.
func (pe *ProtocolEnforcer) HandleConnect(connID string) {
	nonceBytes := make([]byte, 16)
	if _, err := rand.Read(nonceBytes); err != nil {
		return
	}
	nonce := base64.StdEncoding.EncodeToString(nonceBytes)
	ts := time.Now().Unix()

	ch := &ConnectionChallenge{
		Nonce:     nonce,
		Timestamp: ts,
		ServerID:  pe.serverID,
	}

	pe.mu.Lock()
	pe.challenges[connID] = ch
	pe.mu.Unlock()

	msg := map[string]any{
		"type":      "challenge",
		"nonce":     nonce,
		"timestamp": ts,
		"server_id": pe.serverID,
	}
	data, _ := json.Marshal(msg)
	if pe.SendFunc != nil {
		pe.SendFunc(connID, data)
	}
}

// HandleMessage processes an inbound message. Returns (payload, true) when the
// message should be forwarded to pipeline routing. Returns (nil, false) when
// consumed internally (handshake) or rejected.
func (pe *ProtocolEnforcer) HandleMessage(connID string, raw []byte) ([]byte, bool) {
	pe.mu.RLock()
	conn, authenticated := pe.connections[connID]
	ch, hasCh := pe.challenges[connID]
	pe.mu.RUnlock()

	if authenticated {
		pe.mu.Lock()
		payload, err := pe.verifyAndExtract(conn, raw)
		pe.mu.Unlock()
		if err != nil {
			pe.sendError(connID, "message_rejected", err.Error())
			return nil, false
		}
		return payload, true
	}

	if hasCh {
		pe.handleHandshake(connID, ch, raw)
	}
	return nil, false
}

// HandleDisconnect cleans up per-connection state.
func (pe *ProtocolEnforcer) HandleDisconnect(connID string) {
	pe.mu.Lock()
	delete(pe.connections, connID)
	delete(pe.challenges, connID)
	pe.mu.Unlock()

	if v, ok := pe.connToPlayer.LoadAndDelete(connID); ok {
		playerID := v.(string)
		pe.playerToConn.Delete(playerID)
		if pe.OnDisconnect != nil {
			pe.OnDisconnect(connID, playerID)
		}
	}
}

// GetPlayerID returns the playerID associated with a connection, if any.
func (pe *ProtocolEnforcer) GetPlayerID(connID string) string {
	v, ok := pe.connToPlayer.Load(connID)
	if !ok {
		return ""
	}
	return v.(string)
}

// GetConnID returns the connID for a playerID, if any.
func (pe *ProtocolEnforcer) GetConnID(playerID string) string {
	v, ok := pe.playerToConn.Load(playerID)
	if !ok {
		return ""
	}
	return v.(string)
}

// GetConnection returns a copy of the authenticated connection for inspection.
func (pe *ProtocolEnforcer) GetConnection(connID string) (AuthenticatedConnection, bool) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	conn, ok := pe.connections[connID]
	if !ok {
		return AuthenticatedConnection{}, false
	}
	return *conn, true
}

// --- internal helpers ---

func (pe *ProtocolEnforcer) handleHandshake(connID string, ch *ConnectionChallenge, msg []byte) {
	var resp HandshakeResponse
	if err := json.Unmarshal(msg, &resp); err != nil {
		pe.sendError(connID, "invalid_handshake", "malformed handshake response")
		return
	}

	// Verify SDK HMAC: HMAC-SHA256(nonce + timestamp + playerType + sessionID, sdkSecret)
	expected := pe.computeHandshakeSig(ch.Nonce, ch.Timestamp, resp.PlayerType, resp.SessionID)
	if !hmac.Equal([]byte(resp.Signature), []byte(expected)) {
		pe.sendError(connID, "auth_failed", "invalid SDK signature")
		return
	}

	// Extract player identity from auth token.
	var playerID string
	jwtPlayerType, jwtPlayerID, err := extractJWTClaims(resp.AuthToken)
	if err == nil {
		if jwtPlayerType != "" && jwtPlayerType != resp.PlayerType {
			pe.sendError(connID, "auth_failed", "JWT player_type mismatch")
			return
		}
		playerID = jwtPlayerID
	} else {
		// Not a JWT — use auth_token directly as playerID (dev/testing mode).
		playerID = resp.AuthToken
	}

	// Derive per-connection HMAC key via HKDF.
	hkdfReader := hkdf.New(sha256.New, pe.sdkSecret, []byte(ch.Nonce), []byte("dnd-connection-key"))
	hmacKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, hmacKey); err != nil {
		pe.sendError(connID, "server_error", "key derivation failed")
		return
	}

	conn := &AuthenticatedConnection{
		ConnID:     connID,
		PlayerID:   playerID,
		PlayerType: resp.PlayerType,
		SessionID:  resp.SessionID,
		HMACKey:    hmacKey,
		LastSeq:    0,
	}

	pe.mu.Lock()
	pe.connections[connID] = conn
	delete(pe.challenges, connID)
	pe.mu.Unlock()

	pe.connToPlayer.Store(connID, playerID)
	pe.playerToConn.Store(playerID, connID)

	// Run the authenticated callback synchronously before sending handshake_ok.
	if pe.OnAuthenticated != nil {
		pe.OnAuthenticated(connID, resp.PlayerType, resp.SessionID, playerID)
	}

	okMsg := map[string]any{
		"type":     "handshake_ok",
		"hmac_key": base64.StdEncoding.EncodeToString(hmacKey),
	}
	data, _ := json.Marshal(okMsg)
	if pe.SendFunc != nil {
		pe.SendFunc(connID, data)
	}
}

func (pe *ProtocolEnforcer) verifyAndExtract(conn *AuthenticatedConnection, raw []byte) ([]byte, error) {
	var env SignedMessage
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("invalid message envelope: %w", err)
	}

	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, env.Seq)
	mac := hmac.New(sha256.New, conn.HMACKey)
	mac.Write(seqBytes)
	mac.Write(env.Payload)
	expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(env.Signature), []byte(expectedSig)) {
		return nil, errors.New("HMAC verification failed")
	}

	if env.Seq <= conn.LastSeq {
		return nil, fmt.Errorf("sequence replay: got %d, last=%d", env.Seq, conn.LastSeq)
	}
	conn.LastSeq = env.Seq

	return env.Payload, nil
}

func (pe *ProtocolEnforcer) sendError(connID, code, detail string) {
	msg := map[string]any{"type": "error", "code": code, "detail": detail}
	data, _ := json.Marshal(msg)
	if pe.SendFunc != nil {
		pe.SendFunc(connID, data)
	}
}

func (pe *ProtocolEnforcer) computeHandshakeSig(nonce string, timestamp int64, playerType, sessionID string) string {
	msg := nonce + fmt.Sprintf("%d", timestamp) + playerType + sessionID
	mac := hmac.New(sha256.New, pe.sdkSecret)
	mac.Write([]byte(msg))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// extractJWTClaims decodes a JWT's payload section (no signature verification)
// and returns player_type and sub.
func extractJWTClaims(token string) (string, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", errors.New("malformed JWT")
	}
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("decode JWT claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return "", "", fmt.Errorf("parse JWT claims: %w", err)
	}
	pt, _ := claims["player_type"].(string)
	sub, _ := claims["sub"].(string)
	if sub == "" {
		sub = token
	}
	return pt, sub, nil
}
