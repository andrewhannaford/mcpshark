// mcp-client is a minimal MCP client used for testing and demo purposes.
// It sends the MCP initialization handshake to the server on stdin/stdout,
// then sends a tools/list request and waits briefly for a response.
//
// Usage (with mcpshark wrapping an MCP server):
//
//	mcpshark run --name demo -- ./corpus/traces/evil-server/evil-server | \
//	  go run ./corpus/traces/mcp-client
//
// Or pipe directly:
//
//	./corpus/traces/mcp-client/mcp-client | ./corpus/traces/evil-server/evil-server
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
)

func send(v interface{}) {
	b, _ := json.Marshal(v)
	fmt.Fprintf(os.Stdout, "%s\n", b)
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	// 1. Send initialize request.
	send(map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]interface{}{
				"name":    "mcp-client",
				"version": "1.0.0",
			},
		},
	})

	// 2. Read InitializeResult.
	if !sc.Scan() {
		return
	}
	var resp map[string]interface{}
	json.Unmarshal(sc.Bytes(), &resp)
	fmt.Fprintf(os.Stderr, "[client] got initialize result: protocolVersion=%v\n",
		nestedGet(resp, "result", "protocolVersion"))

	// 3. Send initialized notification.
	send(map[string]interface{}{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})

	// 4. Read the next message from the server — for evil-server, this will
	// be a sampling/createMessage request.
	if sc.Scan() {
		var msg map[string]interface{}
		json.Unmarshal(sc.Bytes(), &msg)
		fmt.Fprintf(os.Stderr, "[client] got server message: method=%v\n", msg["method"])

		// Respond to sampling request with a stub result.
		if method, _ := msg["method"].(string); method == "sampling/createMessage" {
			id, _ := json.Marshal(msg["id"])
			sendRaw := func(b []byte) { fmt.Fprintf(os.Stdout, "%s\n", b) }
			resp, _ := json.Marshal(map[string]interface{}{
				"jsonrpc": "2.0",
				"id":      json.RawMessage(id),
				"result": map[string]interface{}{
					"role": "assistant",
					"content": map[string]interface{}{
						"type": "text",
						"text": "[stub response — sampling/createMessage intercepted by mcpshark]",
					},
					"model":      "stub",
					"stopReason": "endTurn",
				},
			})
			sendRaw(resp)
		}
	}
}

func nestedGet(m map[string]interface{}, keys ...string) interface{} {
	var v interface{} = m
	for _, k := range keys {
		mm, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}
