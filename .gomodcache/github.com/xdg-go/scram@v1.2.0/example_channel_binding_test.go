// Copyright 2025 by David A. Golden. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package scram_test

import (
	"fmt"

	"github.com/xdg-go/scram"
)

// ExampleClient_channelBindingModes demonstrates the three channel binding modes
// available when creating authentication conversations.
func Example_channelBindingModes() {
	client, _ := scram.SHA256.NewClient("user", "password", "")

	// Mode 1: No channel binding support
	// Use when: Application doesn't support channel binding at all
	// GS2 header: "n,,"
	conv1 := client.NewConversation()
	msg1, _ := conv1.Step("")
	fmt.Printf("Mode 1 GS2 header: %s\n", msg1[:3])

	// Mode 2: Advertise channel binding support
	// Use when: Application supports CB but server didn't advertise PLUS variants
	// Example: Server advertised "SCRAM-SHA-256" but not "SCRAM-SHA-256-PLUS"
	// GS2 header: "y,,"
	// Security: Helps detect downgrade attacks (MITM stripping PLUS from server list)
	conv2 := client.NewConversationAdvertisingChannelBinding()
	msg2, _ := conv2.Step("")
	fmt.Printf("Mode 2 GS2 header: %s\n", msg2[:3])

	// Mode 3: Use channel binding
	// Use when: Server advertised PLUS variant AND app has TLS connection state
	// GS2 header: "p=<type>,,"
	// Note: In real code, get connState from actual TLS connection
	// var connState *tls.ConnectionState = tlsConn.ConnectionState()
	// cb, _ := scram.NewTLSExporterBinding(connState)
	//
	// For example purposes, create a dummy channel binding.
	cb := scram.ChannelBinding{
		Type: scram.ChannelBindingTLSExporter,
		Data: []byte("example-cb-data"),
	}
	conv3 := client.NewConversationWithChannelBinding(cb)
	msg3, _ := conv3.Step("")
	fmt.Printf("Mode 3 GS2 header: %s\n", msg3[:16])

	// Output:
	// Mode 1 GS2 header: n,,
	// Mode 2 GS2 header: y,,
	// Mode 3 GS2 header: p=tls-exporter,,
}
