package internal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"testing"
)

func TestProtocolEnforcer_ChallengeAndHandshake(t *testing.T) {
	secret := []byte("test-secret")
	pe := NewProtocolEnforcer(secret, "test-server")

	var sentMsgs [][]byte
	pe.SendFunc = func(connID string, msg []byte) bool {
		sentMsgs = append(sentMsgs, msg)
		return true
	}

	// Step 1: HandleConnect should send a challenge
	pe.HandleConnect("conn-1")

	if len(sentMsgs) != 1 {
		t.Fatalf("expected 1 message (challenge), got %d", len(sentMsgs))
	}

	var challenge map[string]any
	if err := json.Unmarshal(sentMsgs[0], &challenge); err != nil {
		t.Fatalf("failed to parse challenge: %v", err)
	}
	if challenge["type"] != "challenge" {
		t.Fatalf("expected challenge type, got %v", challenge["type"])
	}

	nonce := challenge["nonce"].(string)
	ts := int64(challenge["timestamp"].(float64))

	// Step 2: Compute the expected handshake signature
	playerType := "player"
	sessionID := "session-1"
	sigMsg := nonce + fmt.Sprintf("%d", ts) + playerType + sessionID
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigMsg))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := HandshakeResponse{
		Signature:  sig,
		PlayerType: playerType,
		SessionID:  sessionID,
		AuthToken:  "player-123", // plain token (dev mode)
		SDKVersion: "1.0.0",
	}
	respBytes, _ := json.Marshal(resp)

	sentMsgs = sentMsgs[:0]
	payload, forward := pe.HandleMessage("conn-1", respBytes)
	if forward {
		t.Fatal("handshake response should not be forwarded")
	}
	if payload != nil {
		t.Fatal("payload should be nil during handshake")
	}

	// Should have sent handshake_ok
	if len(sentMsgs) != 1 {
		t.Fatalf("expected 1 message (handshake_ok), got %d", len(sentMsgs))
	}

	var okMsg map[string]any
	json.Unmarshal(sentMsgs[0], &okMsg)
	if okMsg["type"] != "handshake_ok" {
		t.Fatalf("expected handshake_ok, got %v", okMsg["type"])
	}

	hmacKeyB64, ok := okMsg["hmac_key"].(string)
	if !ok || hmacKeyB64 == "" {
		t.Fatal("expected hmac_key in handshake_ok")
	}

	// Verify player lookup
	playerID := pe.GetPlayerID("conn-1")
	if playerID != "player-123" {
		t.Fatalf("expected player-123, got %q", playerID)
	}
	connID := pe.GetConnID("player-123")
	if connID != "conn-1" {
		t.Fatalf("expected conn-1, got %q", connID)
	}
}

func TestProtocolEnforcer_SignedMessageVerification(t *testing.T) {
	secret := []byte("test-secret")
	pe := NewProtocolEnforcer(secret, "test-server")

	var sentMsgs [][]byte
	pe.SendFunc = func(connID string, msg []byte) bool {
		sentMsgs = append(sentMsgs, msg)
		return true
	}

	// Complete handshake
	pe.HandleConnect("conn-1")
	var challenge map[string]any
	json.Unmarshal(sentMsgs[0], &challenge)
	nonce := challenge["nonce"].(string)
	ts := int64(challenge["timestamp"].(float64))

	sigMsg := nonce + fmt.Sprintf("%d", ts) + "player" + "session-1"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigMsg))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := HandshakeResponse{
		Signature: sig, PlayerType: "player",
		SessionID: "session-1", AuthToken: "p1",
	}
	respBytes, _ := json.Marshal(resp)
	sentMsgs = sentMsgs[:0]
	pe.HandleMessage("conn-1", respBytes)

	// Get the HMAC key from handshake_ok
	var okMsg map[string]any
	json.Unmarshal(sentMsgs[0], &okMsg)
	hmacKey, _ := base64.StdEncoding.DecodeString(okMsg["hmac_key"].(string))

	// Send a properly signed message
	payload := []byte(`{"type":"game_action","action":"move"}`)
	seq := uint64(1)
	seqBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(seqBytes, seq)
	msgMac := hmac.New(sha256.New, hmacKey)
	msgMac.Write(seqBytes)
	msgMac.Write(payload)
	msgSig := base64.StdEncoding.EncodeToString(msgMac.Sum(nil))

	signed := SignedMessage{Seq: seq, Payload: payload, Signature: msgSig}
	signedBytes, _ := json.Marshal(signed)

	result, forward := pe.HandleMessage("conn-1", signedBytes)
	if !forward {
		t.Fatal("valid signed message should be forwarded")
	}
	if string(result) != string(payload) {
		t.Fatalf("expected payload %q, got %q", string(payload), string(result))
	}
}

func TestProtocolEnforcer_ReplayRejection(t *testing.T) {
	secret := []byte("test-secret")
	pe := NewProtocolEnforcer(secret, "test-server")

	var sentMsgs [][]byte
	pe.SendFunc = func(connID string, msg []byte) bool {
		sentMsgs = append(sentMsgs, msg)
		return true
	}

	// Complete handshake
	pe.HandleConnect("conn-1")
	var challenge map[string]any
	json.Unmarshal(sentMsgs[0], &challenge)
	nonce := challenge["nonce"].(string)
	ts := int64(challenge["timestamp"].(float64))

	sigMsg := nonce + fmt.Sprintf("%d", ts) + "player" + "s1"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigMsg))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := HandshakeResponse{Signature: sig, PlayerType: "player", SessionID: "s1", AuthToken: "p1"}
	respBytes, _ := json.Marshal(resp)
	sentMsgs = sentMsgs[:0]
	pe.HandleMessage("conn-1", respBytes)

	var okMsg map[string]any
	json.Unmarshal(sentMsgs[0], &okMsg)
	hmacKey, _ := base64.StdEncoding.DecodeString(okMsg["hmac_key"].(string))

	makeSignedMsg := func(seq uint64, payload []byte) []byte {
		seqBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(seqBytes, seq)
		msgMac := hmac.New(sha256.New, hmacKey)
		msgMac.Write(seqBytes)
		msgMac.Write(payload)
		msgSig := base64.StdEncoding.EncodeToString(msgMac.Sum(nil))
		signed := SignedMessage{Seq: seq, Payload: payload, Signature: msgSig}
		b, _ := json.Marshal(signed)
		return b
	}

	// Send seq=1 — should succeed
	_, forward := pe.HandleMessage("conn-1", makeSignedMsg(1, []byte(`{"action":"a"}`)))
	if !forward {
		t.Fatal("seq=1 should be forwarded")
	}

	// Replay seq=1 — should be rejected
	_, forward = pe.HandleMessage("conn-1", makeSignedMsg(1, []byte(`{"action":"a"}`)))
	if forward {
		t.Fatal("replay of seq=1 should be rejected")
	}

	// seq=2 should succeed
	_, forward = pe.HandleMessage("conn-1", makeSignedMsg(2, []byte(`{"action":"b"}`)))
	if !forward {
		t.Fatal("seq=2 should be forwarded")
	}
}

func TestProtocolEnforcer_Disconnect(t *testing.T) {
	secret := []byte("test-secret")
	pe := NewProtocolEnforcer(secret, "test-server")

	var disconnectedPlayer string
	pe.OnDisconnect = func(connID, playerID string) {
		disconnectedPlayer = playerID
	}

	pe.SendFunc = func(connID string, msg []byte) bool { return true }

	// Complete handshake
	pe.HandleConnect("conn-1")
	var sentMsgs [][]byte
	pe.SendFunc = func(connID string, msg []byte) bool {
		sentMsgs = append(sentMsgs, msg)
		return true
	}
	pe.HandleConnect("conn-1")
	var challenge map[string]any
	json.Unmarshal(sentMsgs[0], &challenge)
	nonce := challenge["nonce"].(string)
	ts := int64(challenge["timestamp"].(float64))

	sigMsg := nonce + fmt.Sprintf("%d", ts) + "player" + "s1"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(sigMsg))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	resp := HandshakeResponse{Signature: sig, PlayerType: "player", SessionID: "s1", AuthToken: "p1"}
	respBytes, _ := json.Marshal(resp)
	pe.HandleMessage("conn-1", respBytes)

	pe.HandleDisconnect("conn-1")

	if disconnectedPlayer != "p1" {
		t.Fatalf("expected OnDisconnect for p1, got %q", disconnectedPlayer)
	}
	if pe.GetPlayerID("conn-1") != "" {
		t.Fatal("player mapping should be cleared after disconnect")
	}
}

func TestProtocolEnforcer_BadSignatureRejected(t *testing.T) {
	secret := []byte("test-secret")
	pe := NewProtocolEnforcer(secret, "test-server")

	var sentMsgs [][]byte
	pe.SendFunc = func(connID string, msg []byte) bool {
		sentMsgs = append(sentMsgs, msg)
		return true
	}

	pe.HandleConnect("conn-1")
	var challenge map[string]any
	json.Unmarshal(sentMsgs[0], &challenge)

	resp := HandshakeResponse{
		Signature:  "bad-signature",
		PlayerType: "player",
		SessionID:  "s1",
		AuthToken:  "p1",
	}
	respBytes, _ := json.Marshal(resp)

	sentMsgs = sentMsgs[:0]
	pe.HandleMessage("conn-1", respBytes)

	// Should have sent an error, not handshake_ok
	if len(sentMsgs) != 1 {
		t.Fatalf("expected 1 error message, got %d", len(sentMsgs))
	}
	var errMsg map[string]any
	json.Unmarshal(sentMsgs[0], &errMsg)
	if errMsg["type"] != "error" {
		t.Fatalf("expected error message, got %v", errMsg["type"])
	}
}
