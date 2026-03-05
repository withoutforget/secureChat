package client

type Client interface {
	Take(id string) error
	Keep(id string) error
	Send(id string, data []byte) error
	Recv(id string) (<-chan []byte, error)
}
