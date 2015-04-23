package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

type KeyPair struct {
	public  *[32]byte
	private *[32]byte
}

type SecureReader struct {
	r  io.Reader
	kp *KeyPair
}

func (sr SecureReader) Read(p []byte) (n int, err error) {

	// The maximum expected size of message is 32 kilobytes
	buf := make([]byte, 32*1024)

	n, err = sr.r.Read(buf)
	if err != nil {
		return 0, err
	}

	// Nonce must be a 24 byte array for the nacl Open method
	if n < 24 {
		return 0, fmt.Errorf("Nonce was %d bytes. Must be 24 bytes.", n)
	}
	var nonce [24]byte

	copy(nonce[:], buf[:24])

	opened, ok := box.Open(nil, buf[24:n], &nonce, sr.kp.public, sr.kp.private)
	if ok != true {
		return 0, fmt.Errorf("Could not decrypt message.")
	}

	copy(p, opened)

	return len(opened), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	return &SecureReader{r, &KeyPair{private: priv, public: pub}}
}

type SecureWriter struct {
	w  io.Writer
	kp *KeyPair
}

func (sw SecureWriter) Write(p []byte) (n int, err error) {
	nonce, err := getNonce()

	if err != nil {
		return 0, err
	}

	sealed := box.Seal(nonce[:], p, &nonce, sw.kp.public, sw.kp.private)
	return sw.w.Write(sealed)
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	return &SecureWriter{w, &KeyPair{private: priv, public: pub}}
}

func getNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nonce, fmt.Errorf("Could not read from rand.Read(): %s.", err)
	}
	return nonce, nil
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	return nil, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	return nil
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
