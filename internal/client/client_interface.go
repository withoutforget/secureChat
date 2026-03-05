package client

// Client is the transport layer for the relay server.
type Client interface {
	Take(id string) error
	Keep(id string) error
	Send(targetID string, senderID string, data []byte) error
	Recv(id string) (<-chan Envelope, error)
}
