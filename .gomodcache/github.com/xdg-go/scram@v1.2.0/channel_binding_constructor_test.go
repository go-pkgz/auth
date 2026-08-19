// Copyright 2025 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// === Helpers for Test Certs ===

// Helper function to generate a test certificate and private key
func generateTestCertAndKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assertNoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	assertNoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	assertNoError(t, err)

	return priv, certDER
}

// Helper function to create a test certificate with a mocked signature
// algorithm.
func mockTestCert(t *testing.T, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()

	_, certDER := generateTestCertAndKey(t)
	cert, err := x509.ParseCertificate(certDER)
	assertNoError(t, err)

	// Override the signature algorithm in the parsed cert to test different hash behaviors
	// What matters for server endpoint channel binding is the certificate's Raw
	// bytes and the SignatureAlgorithm field, not the actual key type match.
	cert.SignatureAlgorithm = sigAlg

	return cert
}

// Helper function to create a mock TLS connection state with a certificate
func createMockConnState(t *testing.T, cert *x509.Certificate) *tls.ConnectionState {
	t.Helper()

	return &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{cert},
	}
}

// Helper function to set up a TLS server with a test certificate
func setupTLSServer(t *testing.T) net.Listener {
	t.Helper()

	priv, certDER := generateTestCertAndKey(t)

	// Create TLS config
	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}

	// Create listener
	listener, err := tls.Listen("tcp", "localhost:0", config)
	assertNoError(t, err)

	return listener
}

// Helper function to connect to a TLS server
func connectTLSClient(t *testing.T, serverAddr string) *tls.Conn {
	t.Helper()

	config := &tls.Config{
		InsecureSkipVerify: true, // Self-signed cert
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", serverAddr, config)
	assertNoError(t, err)

	return conn
}

// === Binding Constructors ===

func TestNewTLSUniqueBinding(t *testing.T) {
	testData := []byte("test-tls-unique-data")

	cb := NewTLSUniqueBinding(testData)

	if cb.Type != ChannelBindingTLSUnique {
		t.Errorf("Expected type %q, got %q", ChannelBindingTLSUnique, cb.Type)
	}

	if string(cb.Data) != string(testData) {
		t.Errorf("Expected data %q, got %q", testData, cb.Data)
	}

	if !cb.IsSupported() {
		t.Error("Expected channel binding to be supported")
	}

	// Verify defensive copy: modifying original data shouldn't affect channel binding
	originalData := []byte{0x01, 0x02, 0x03, 0x04}
	cb2 := NewTLSUniqueBinding(originalData)

	// Modify the original slice
	originalData[0] = 0xFF
	originalData[1] = 0xFF

	// Channel binding data should be unchanged
	if cb2.Data[0] != 0x01 || cb2.Data[1] != 0x02 {
		t.Errorf("Channel binding data was modified when original slice changed: got %v, expected [1 2 3 4]", cb2.Data)
	}
}

func TestNewTLSServerEndpointBinding(t *testing.T) {
	tests := []struct {
		name    string
		sigAlg  x509.SignatureAlgorithm
		hashLen int
	}{
		{"SHA1WithRSA", x509.SHA1WithRSA, 32}, // Upgrade from SHA-1 to SHA-256
		{"SHA256WithRSA", x509.SHA256WithRSA, 32},
		{"ECDSAWithSHA256", x509.ECDSAWithSHA256, 32},
		{"ECDSAWithSHA384", x509.ECDSAWithSHA384, 48},
		{"ECDSAWithSHA512", x509.ECDSAWithSHA512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := mockTestCert(t, tt.sigAlg)
			connState := createMockConnState(t, cert)

			cb, err := NewTLSServerEndpointBinding(connState)
			assertNoError(t, err)

			if cb.Type != ChannelBindingTLSServerEndpoint {
				t.Errorf("Expected type %q, got %q", ChannelBindingTLSServerEndpoint, cb.Type)
			}

			if len(cb.Data) != tt.hashLen {
				t.Errorf("Expected hash length %d, got %d", tt.hashLen, len(cb.Data))
			}

			if !cb.IsSupported() {
				t.Error("Expected channel binding to be supported")
			}
		})
	}
}

func TestNewTLSServerEndpointBinding_NoPeerCertificates(t *testing.T) {
	connState := &tls.ConnectionState{
		Version:           tls.VersionTLS13,
		HandshakeComplete: true,
		PeerCertificates:  []*x509.Certificate{},
	}

	_, err := NewTLSServerEndpointBinding(connState)
	assertErrorContains(t, err, "no peer certificates")
}

func TestNewTLSServerEndpointBinding_NilConnectionState(t *testing.T) {
	_, err := NewTLSServerEndpointBinding(nil)
	assertErrorContains(t, err, "connection state is nil")
}

func TestNewTLSExporterBinding(t *testing.T) {
	_, err := NewTLSExporterBinding(nil)
	assertErrorContains(t, err, "connection state is nil")
}

func TestNewTLSExporterBinding_RealTLS13(t *testing.T) {
	// Set up TLS server
	listener := setupTLSServer(t)
	defer listener.Close()

	// Channel to receive server connection state and coordinate cleanup
	serverStateChan := make(chan *tls.ConnectionState, 1)
	errChan := make(chan error, 1)
	doneChan := make(chan struct{})

	// Accept connection in goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		defer conn.Close()

		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			errChan <- errors.New("failed to cast to *tls.Conn")
			return
		}

		// Ensure handshake completes
		err = tlsConn.Handshake()
		if err != nil {
			errChan <- err
			return
		}

		// Get server connection state
		state := tlsConn.ConnectionState()
		serverStateChan <- &state

		// Wait for test to complete before closing connection
		<-doneChan
	}()

	// Connect client
	clientConn := connectTLSClient(t, listener.Addr().String())
	defer func() {
		close(doneChan) // Signal server to close
		clientConn.Close()
	}()

	// Ensure handshake completes on client side
	err := clientConn.Handshake()
	assertNoError(t, err)

	// Get client connection state
	clientState := clientConn.ConnectionState()

	// Wait for server connection state
	var serverState *tls.ConnectionState
	select {
	case serverState = <-serverStateChan:
	case err := <-errChan:
		t.Fatalf("Server error: %v", err)
	}

	// Test NewTLSExporterBinding on client side
	clientCB, err := NewTLSExporterBinding(&clientState)
	assertNoError(t, err)

	if clientCB.Type != ChannelBindingTLSExporter {
		t.Errorf("Expected type %q, got %q", ChannelBindingTLSExporter, clientCB.Type)
	}

	if len(clientCB.Data) == 0 {
		t.Error("Expected non-empty channel binding data")
	}

	if !clientCB.IsSupported() {
		t.Error("Expected channel binding to be supported")
	}

	// Test NewTLSExporterBinding on server side
	serverCB, err := NewTLSExporterBinding(serverState)
	assertNoError(t, err)

	if serverCB.Type != ChannelBindingTLSExporter {
		t.Errorf("Expected type %q, got %q", ChannelBindingTLSExporter, serverCB.Type)
	}

	if len(serverCB.Data) == 0 {
		t.Error("Expected non-empty channel binding data")
	}

	if !serverCB.IsSupported() {
		t.Error("Expected channel binding to be supported")
	}

	// Verify both sides export the same keying material
	if !clientCB.Matches(serverCB) {
		t.Errorf("Client and server channel binding data should match.\nClient: %x\nServer: %x",
			clientCB.Data, serverCB.Data)
	}
}
