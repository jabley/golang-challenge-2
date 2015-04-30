package main

import (
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/nacl/box"
)

// keyPair contains public and private keys for encryption
type keyPair struct {
	public  *[32]byte
	private *[32]byte
}

type secureReader struct {
	fr *Framer
	kp *keyPair
}

func (sr *secureReader) Read(p []byte) (n int, err error) {
	// Was all of the previous message frame been consumed?
	if sr.fr.HasUnreadPortion() {
		return sr.fr.ReadPayload(p)
	}

	fh, err := sr.fr.ReadFrameHeader(sr.fr.r)

	if err != nil {
		return 0, fmt.Errorf("Unable to read frame header: %v\n", err)
	}

	payload := sr.fr.getReadBuf(fh.Length)

	if _, err := io.ReadFull(io.LimitReader(sr.fr.r, int64(fh.Length)), payload); err != nil {
		return 0, err
	}

	opened, ok := box.Open(nil, payload, &fh.Nonce, sr.kp.public, sr.kp.private)
	if !ok {
		return 0, fmt.Errorf("Could not decrypt message.")
	}

	sr.fr.unread = opened
	return sr.fr.ReadPayload(p)
}

// NewSecureReader instantiates a new secureReader
func NewSecureReader(r io.Reader, priv, pub *[32]byte) io.Reader {
	fr := NewFramer(nil, r)
	return &secureReader{fr, &keyPair{private: priv, public: pub}}
}

type secureWriter struct {
	fr *Framer
	kp *keyPair
}

func (sw *secureWriter) Write(p []byte) (n int, err error) {
	nonce, err := sw.fr.getNonce()

	if err != nil {
		return 0, err
	}

	sealed := box.Seal(nonce[:], p, &nonce, sw.kp.public, sw.kp.private)

	return sw.fr.Write(sealed)
}

// NewSecureWriter instantiates a new secureWriter
func NewSecureWriter(w io.Writer, priv, pub *[32]byte) io.Writer {
	fr := NewFramer(w, nil)
	return &secureWriter{fr, &keyPair{private: priv, public: pub}}
}

type secureReadWriteCloser struct {
	reader io.Reader
	writer io.Writer
}

func (srwc *secureReadWriteCloser) Read(p []byte) (int, error) {
	return srwc.reader.Read(p)
}

func (srwc *secureReadWriteCloser) Write(p []byte) (int, error) {
	return srwc.writer.Write(p)
}

func (srwc *secureReadWriteCloser) Close() error {
	return nil
}

type handshake struct {
	localPublicKey  [32]byte
	remotePublicKey [32]byte
}

// Dial generates a private/public key pair,
// connects to the server, perform the handshake
// and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	// generate a private/public key pair
	kp, err := generateKeyPair()
	if err != nil {
		return nil, err
	}

	// connect to the server
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}

	hs := &handshake{
		localPublicKey: *kp.public,
	}

	// perform the handshake
	err = negotiate(conn, hs)

	if err != nil {
		return nil, err
	}

	// return a reader/writer
	return &secureReadWriteCloser{
		NewSecureReader(conn, kp.private, &hs.remotePublicKey),
		NewSecureWriter(conn, kp.private, &hs.remotePublicKey),
	}, nil
}

func generateKeyPair() (*keyPair, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &keyPair{public: public, private: private}, nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	defer l.Close()

	kp, err := generateKeyPair()

	if err != nil {
		return err
	}

	for {
		conn, e := l.Accept()
		if e != nil {
			return e
		}
		// Should we use a KeyPair per client?
		serve(conn, kp)
	}
}

func serve(conn net.Conn, kp *keyPair) error {
	defer conn.Close()

	hs := &handshake{
		localPublicKey: *kp.public,
	}

	if err := negotiate(conn, hs); err != nil {
		return err
	}

	secureR := NewSecureReader(conn, kp.private, &hs.remotePublicKey)
	secureW := NewSecureWriter(conn, kp.private, &hs.remotePublicKey)

	buf := make([]byte, 32*1024)
	n, _ := secureR.Read(buf)
	n, _ = secureW.Write(buf[:n])

	return nil
}

func negotiate(conn net.Conn, hs *handshake) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	err := binary.Write(conn, binary.LittleEndian, hs.localPublicKey)

	if err != nil {
		return err
	}

	err = binary.Read(conn, binary.LittleEndian, &hs.remotePublicKey)

	if err != nil {
		return err
	}

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
