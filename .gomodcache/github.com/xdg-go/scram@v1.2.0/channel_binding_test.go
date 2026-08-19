// Copyright 2025 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// === Helpers ===

// Authentication flow step names
const (
	stepClientFirst      = "client first"
	stepServerFirst      = "server first"
	stepClientFinal      = "client final"
	stepServerFinal      = "server final"
	stepClientValidation = "client validation"
	stepFinalValidation  = "final validation"
	stepFinished         = "finished"
)

// assertErrorContains verifies that err is non-nil and contains all specified substrings.
func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
}

// assertErrorContains verifies that err is non-nil and contains all specified substrings.
func assertErrorContains(t *testing.T, err error, substr string) {
	t.Helper()
	if err == nil {
		t.Fatal("Expected error, got nil")
	}
	if !strings.Contains(err.Error(), substr) {
		t.Errorf("Expected error to contain %q, got: %v", substr, err)
	}
}

func assertFinishedSuccessfully(t *testing.T, step string, err error) {
	t.Helper()
	assertNoError(t, err)
	if step != stepFinished {
		t.Errorf("Expected authentication to finish successfully, got stuck at step %q", step)
	}
}

// assertErrorAtStep verifies that an error occurred at the expected step and contains expected substrings.
func assertErrorAtStep(t *testing.T, step string, err error, expectedStep string, expectedErrSubstrs ...string) {
	t.Helper()
	if step != expectedStep {
		t.Errorf("Expected error at step %q, got %q", expectedStep, step)
	}
	for _, substr := range expectedErrSubstrs {
		assertErrorContains(t, err, substr)
	}
}

// mockCredLookupFcn returns a CredentialLookup function for testing with the given password.
// Uses a fixed salt and iteration count for consistent test behavior.
func mockCredLookupFcn(password string) CredentialLookup {
	return func(username string) (StoredCredentials, error) {
		client, _ := SHA256.NewClient(username, password, "")
		salt := []byte("QSXCR+Q6sek8bf92")
		return client.GetStoredCredentials(KeyFactors{Salt: string(salt), Iters: 4096}), nil
	}
}

// setupClientServer creates a client and server for testing with standard test credentials.
func setupClientServer(t *testing.T) (*Client, *Server) {
	t.Helper()
	client, err := SHA256.NewClient("user", "pencil", "")
	assertNoError(t, err)
	server, err := SHA256.NewServer(mockCredLookupFcn("pencil"))
	assertNoError(t, err)
	return client, server
}

// setupConversations creates client and server conversations with the specified channel bindings.
func setupConversations(t *testing.T, client *Client, server *Server, clientCB, serverCB ChannelBinding, required bool) (*ClientConversation, *ServerConversation) {
	var clientConv *ClientConversation
	if clientCB.IsSupported() {
		clientConv = client.NewConversationWithChannelBinding(clientCB)
	} else {
		clientConv = client.NewConversation()
	}

	var serverConv *ServerConversation
	if required {
		if !serverCB.IsSupported() {
			t.Fatal("Server channel binding must be supported when required is true")
		}
		serverConv = server.NewConversationWithChannelBindingRequired(serverCB)
	} else if serverCB.IsSupported() {
		serverConv = server.NewConversationWithChannelBinding(serverCB)
	} else {
		serverConv = server.NewConversation()
	}

	return clientConv, serverConv
}

// runFullAuthFlow executes a complete SCRAM authentication between the given
// client and server conversations. Returns the name of the step where an error
// occurred (if any) and the error itself.
func runFullAuthFlow(clientConv *ClientConversation, serverConv *ServerConversation) (string, error) {
	clientFirst, err := clientConv.Step("")
	if err != nil {
		return stepClientFirst, err
	}

	serverFirst, err := serverConv.Step(clientFirst)
	if err != nil {
		return stepServerFirst, err
	}

	clientFinal, err := clientConv.Step(serverFirst)
	if err != nil {
		return stepClientFinal, err
	}

	serverFinal, err := serverConv.Step(clientFinal)
	if err != nil {
		return stepServerFinal, err
	}

	_, err = clientConv.Step(serverFinal)
	if err != nil {
		return stepClientValidation, err
	}

	if !clientConv.Valid() || !serverConv.Valid() {
		return stepFinalValidation, errors.New("authentication failed: conversations not valid")
	}

	return stepFinished, nil
}

// extractNonce parses the nonce from a server-first message.
// Server-first format: r=<nonce>,s=<salt>,i=<iterations>
func extractNonce(serverFirst string) string {
	parts := strings.Split(serverFirst, ",")
	noncePart := parts[0] // r=clientnonce123servernonce...
	return noncePart[2:]  // Strip "r=" prefix
}

// setupForClientFinal creates conversations and advances to the point where
// client-final is expected. Returns the server conversation ready to receive
// client-final, the nonce to use, and the GS2 header string.
func setupForClientFinal(t *testing.T, client *Client, server *Server, cb ChannelBinding) (*ServerConversation, string, string) {
	t.Helper()
	clientConv, serverConv := setupConversations(t, client, server, cb, cb, false)

	clientFirst, err := clientConv.Step("")
	assertNoError(t, err)

	serverFirst, err := serverConv.Step(clientFirst)
	assertNoError(t, err)

	nonce := extractNonce(serverFirst)
	gs2Header := "p=" + string(cb.Type) + ",,"

	return serverConv, nonce, gs2Header
}

// buildClientFinal constructs a valid client-final message from components.
func buildClientFinal(nonce, gs2Header string, cbData []byte, proof string) string {
	cbMsg := append([]byte(gs2Header), cbData...)
	cAttr := base64.StdEncoding.EncodeToString(cbMsg)
	return fmt.Sprintf("c=%s,r=%s,p=%s", cAttr, nonce, proof)
}

// === Basic method tests ===

func TestChannelBindingIsSupported(t *testing.T) {
	// Positive case
	if !(ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test")}.IsSupported()) {
		t.Error("Channel binding with type and data should be supported")
	}

	// Negative cases
	if (ChannelBinding{}.IsSupported()) {
		t.Error("Empty channel binding should not be supported")
	}
	if (ChannelBinding{Type: ChannelBindingTLSExporter}.IsSupported()) {
		t.Error("Channel binding with type but no data should not be supported")
	}
}

func TestChannelBindingMatches_Data(t *testing.T) {
	cb1 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test")}
	cb2 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test")}
	cb3 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("different")}

	if !cb1.Matches(cb2) {
		t.Error("Identical channel bindings should match")
	}
	if cb1.Matches(cb3) {
		t.Error("Different data should not match")
	}
}

func TestChannelBindingMatches_Type(t *testing.T) {
	cb1 := ChannelBinding{Type: ChannelBindingTLSUnique, Data: []byte("test")}
	cb2 := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test")}

	if cb1.Matches(cb2) {
		t.Error("Different types should not match")
	}
}

// === Protocol encoding tests ===

func TestChannelBindingGS2Header(t *testing.T) {
	username := "user"
	password := "pencil"

	// Verify that client-first messages contain correct GS2 headers per RFC 5802.
	tests := []struct {
		name           string
		setupConv      func(client *Client) *ClientConversation
		expectedPrefix string
		authzID        string
	}{
		{
			name:           "No channel binding - flag n",
			setupConv:      func(client *Client) *ClientConversation { return client.NewConversation() },
			expectedPrefix: "n,,",
		},
		{
			name:           "No channel binding - flag n, with authzID",
			setupConv:      func(client *Client) *ClientConversation { return client.NewConversation() },
			authzID:        "admin",
			expectedPrefix: "n,a=admin,",
		},
		{
			name: "With tls-exporter channel binding - flag p",
			setupConv: func(client *Client) *ClientConversation {
				return client.NewConversationWithChannelBinding(ChannelBinding{
					Type: ChannelBindingTLSExporter,
					Data: []byte{0x01, 0x02, 0x03},
				})
			},
			expectedPrefix: "p=tls-exporter,,",
		},
		{
			name: "With tls-exporter channel binding - flag p, with authzID",
			setupConv: func(client *Client) *ClientConversation {
				return client.NewConversationWithChannelBinding(ChannelBinding{
					Type: ChannelBindingTLSExporter,
					Data: []byte{0x01, 0x02, 0x03},
				})
			},
			authzID:        "admin",
			expectedPrefix: "p=tls-exporter,a=admin,",
		},
		{
			name:           "Advertising channel binding - flag y",
			setupConv:      func(client *Client) *ClientConversation { return client.NewConversationAdvertisingChannelBinding() },
			expectedPrefix: "y,,",
		},
		{
			name:           "Advertising channel binding - flag y, with authzID",
			setupConv:      func(client *Client) *ClientConversation { return client.NewConversationAdvertisingChannelBinding() },
			authzID:        "admin",
			expectedPrefix: "y,a=admin,",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := SHA256.NewClient(username, password, tt.authzID)
			assertNoError(t, err)
			conv := tt.setupConv(client)
			clientFirst, err := conv.Step("")
			assertNoError(t, err)

			if !strings.HasPrefix(clientFirst, tt.expectedPrefix) {
				t.Errorf("Expected client-first to start with %q, got %q",
					tt.expectedPrefix, clientFirst)
			}
		})
	}
}

// === Channel binding conversation tests ===

func TestChannelBinding_Success_NoBinding(t *testing.T) {
	client, server := setupClientServer(t)
	clientConv, serverConv := setupConversations(t, client, server, ChannelBinding{}, ChannelBinding{}, false)
	step, err := runFullAuthFlow(clientConv, serverConv)
	assertFinishedSuccessfully(t, step, err)
}

func TestChannelBinding_Success_AllTypes(t *testing.T) {
	bindingTypes := []ChannelBindingType{
		ChannelBindingTLSUnique,
		ChannelBindingTLSServerEndpoint,
		ChannelBindingTLSExporter,
	}

	for _, cbType := range bindingTypes {
		t.Run(string(cbType), func(t *testing.T) {
			cbData := []byte("test-data-for-" + string(cbType))
			cb := ChannelBinding{Type: cbType, Data: cbData}

			client, server := setupClientServer(t)
			clientConv, serverConv := setupConversations(t, client, server, cb, cb, false)
			step, err := runFullAuthFlow(clientConv, serverConv)
			assertFinishedSuccessfully(t, step, err)
		})
	}
}

func TestChannelBinding_Success_ClientBindingNotRequired(t *testing.T) {
	serverCB := ChannelBinding{Type: ChannelBindingTLSExporter, Data: []byte("test-data")}

	client, server := setupClientServer(t)
	clientConv, serverConv := setupConversations(t, client, server, ChannelBinding{}, serverCB, false)
	step, err := runFullAuthFlow(clientConv, serverConv)
	assertFinishedSuccessfully(t, step, err)
}

func TestChannelBinding_Failure_UnsupportedType(t *testing.T) {
	client, server := setupClientServer(t)

	// Run authentication conversation - client with tls-exporter, server with tls-server-end-point
	clientCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	}
	serverCB := ChannelBinding{
		Type: ChannelBindingTLSServerEndpoint,
		Data: []byte("test-data"),
	}
	clientConv, serverConv := setupConversations(t, client, server, clientCB, serverCB, false)

	// Server should reject the unsupported channel binding type, reporting both types seen.
	step, err := runFullAuthFlow(clientConv, serverConv)
	assertErrorAtStep(t, step, err, stepServerFirst, "tls-exporter", "tls-server-end-point")
}

func TestChannelBinding_Failure_DataMismatch(t *testing.T) {
	client, server := setupClientServer(t)

	// Run authentication conversation with mismatched channel binding
	clientCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("client-data"),
	}
	serverCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("server-data"),
	}
	clientConv, serverConv := setupConversations(t, client, server, clientCB, serverCB, false)

	step, err := runFullAuthFlow(clientConv, serverConv)
	assertErrorAtStep(t, step, err, stepServerFinal, "channel binding mismatch")
}

func TestChannelBinding_Failure_Malformed(t *testing.T) {
	client, server := setupClientServer(t)
	cbData := []byte("test-cb-data")
	cb := NewTLSUniqueBinding(cbData)
	mockproof := base64.StdEncoding.EncodeToString([]byte("mock-proof"))

	t.Run("Invalid base64 in c attribute", func(t *testing.T) {
		serverConv, nonce, _ := setupForClientFinal(t, client, server, cb)

		// Construct malformed message with invalid base64
		clientFinal := fmt.Sprintf("c=not-valid-base64!!!,r=%s,p=%s", nonce, mockproof)

		_, err := serverConv.Step(clientFinal)
		assertErrorContains(t, err, "illegal base64 data")
	})

	t.Run("Truncated channel binding data", func(t *testing.T) {
		serverConv, nonce, gs2Header := setupForClientFinal(t, client, server, cb)

		// Use helper to build valid message structure, but with truncated data
		clientFinal := buildClientFinal(nonce, gs2Header, cbData[:2], mockproof)

		_, err := serverConv.Step(clientFinal)
		assertErrorContains(t, err, "channel binding mismatch")
	})
}

func TestChannelBinding_Failure_ServerDoesntSupportBinding(t *testing.T) {
	client, server := setupClientServer(t)

	// Run authentication conversation - client with channel binding, server without
	clientCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	}
	clientConv, serverConv := setupConversations(t, client, server, clientCB, ChannelBinding{}, false)

	// Server should reject the client's channel binding request
	step, err := runFullAuthFlow(clientConv, serverConv)
	assertErrorAtStep(t, step, err, stepServerFirst, "client requires channel binding")
}

func TestChannelBinding_Failure_BindingRequired(t *testing.T) {
	client, server := setupClientServer(t)

	// Run authentication conversation - client without channel binding, server requires it
	serverCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	}
	clientConv, serverConv := setupConversations(t, client, server, ChannelBinding{}, serverCB, true)

	// Server should reject due to channel binding being required at server first step
	step, err := runFullAuthFlow(clientConv, serverConv)
	assertErrorAtStep(t, step, err, stepServerFirst, "server requires channel binding")
}

func TestChannelBinding_Failure_RejectDowngrade(t *testing.T) {
	client, server := setupClientServer(t)

	// Server with optional channel binding, client thinks server does not have
	// channel binding but advertises that client supports it.
	serverCB := ChannelBinding{
		Type: ChannelBindingTLSExporter,
		Data: []byte("test-data"),
	}
	serverConv := server.NewConversationWithChannelBinding(serverCB)
	clientConv := client.NewConversationAdvertisingChannelBinding()

	step, err := runFullAuthFlow(clientConv, serverConv)
	assertErrorAtStep(t, step, err, stepServerFirst, "downgrade attack detected")
}
