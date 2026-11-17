// Package mcp implements a minimal Model Context Protocol client: the JSON-RPC
// 2.0 message layer, the initialize handshake, and enumeration of the tool,
// resource, and prompt surface with pagination.
package mcp

import (
	"encoding/json"
	"fmt"
)

// jsonRPCVersion is the only JSON-RPC version MCP uses.
const jsonRPCVersion = "2.0"

// Request is a JSON-RPC 2.0 request. A request with a nil ID is a
// notification, which expects no response.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  interface{}     `json:"params,omitempty"`
}

// Response is a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError is a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// newRequest builds a request with an integer id encoded as raw JSON.
func newRequest(id int, method string, params interface{}) Request {
	raw, _ := json.Marshal(id)
	return Request{
		JSONRPC: jsonRPCVersion,
		ID:      raw,
		Method:  method,
		Params:  params,
	}
}

// newNotification builds a notification (no id).
func newNotification(method string, params interface{}) Request {
	return Request{JSONRPC: jsonRPCVersion, Method: method, Params: params}
}
