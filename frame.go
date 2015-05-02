package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
)

// +--------------------------+
// | Length of data (24 bits) |
// +--------------------------+
// | Nonce (24 bytes)         |
// +----------------------------------+
// |               Data               |
// +----------------------------------+

const frameHeaderLen = 27

// ErrFrameTooLarge is returned from Framer.ReadFrame when the peer tries to send too much data.
var ErrFrameTooLarge = errors.New("frame too large")

// frame header bytes.
// Used only by ReadFrameHeader.
var fhBytes = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, frameHeaderLen)
		return &buf
	},
}

// A Framer reads and writes Frames
type Framer struct {
	w io.Writer
	r io.Reader
	// Pluggable function for allocating memory for read buffer
	getReadBuf func(size uint32) []byte
	readBuf    []byte // cache for default getReadBuf

	unread []byte // used to hold the decoded message when reading

	werr error // the first write error that occurred
}

// NewFramer returns a Framer that writes frames to w and reads them from r.
func NewFramer(w io.Writer, r io.Reader) *Framer {
	fr := &Framer{
		r: r,
	}
	fr.w = stickyErrWriter{w, &fr.werr}

	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	return fr
}

// HasUnreadPortion returns true if not all of the previous frame has been consumed, otherwise false.
func (fr *Framer) HasUnreadPortion() bool {
	return fr.unread != nil
}

// Read reads up to len(p) bytes into p.
func (fr *Framer) Read(p []byte) (int, error) {
	dstLen := len(p)
	srcLen := len(fr.unread)

	if srcLen == 0 {
		fr.unread = nil
		return 0, io.EOF
	}

	if dstLen >= srcLen {
		copy(p, fr.unread)
		fr.unread = fr.unread[srcLen:]
		return srcLen, nil
	}

	// We need to buffer the read of this message - provided buffer is too small to hold the entire message
	copy(p, fr.unread[:dstLen])
	fr.unread = fr.unread[dstLen:]
	return dstLen, nil
}

func (fr *Framer) getNonce() ([24]byte, error) {
	var nonce [24]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nonce, fmt.Errorf("Could not read from rand.Read(): %s.", err)
	}
	return nonce, nil
}

// ReadFrameHeader reads 27 bytes from r and returns a FrameHeader.
func (fr *Framer) ReadFrameHeader(r io.Reader) (FrameHeader, error) {
	bufp := fhBytes.Get().(*[]byte)
	defer fhBytes.Put(bufp)
	return readFrameHeader(*bufp, r)
}

func readFrameHeader(buf []byte, r io.Reader) (FrameHeader, error) {
	if _, err := io.ReadFull(r, buf[:frameHeaderLen]); err != nil {
		return FrameHeader{}, err
	}

	var nonce [24]byte

	copy(nonce[:], buf[3:frameHeaderLen])

	return FrameHeader{
		Length: (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Nonce:  nonce,
	}, nil
}

func (fr *Framer) Write(p []byte) (int, error) {
	length := len(p) - 24

	if length >= (1 << 24) {
		return 0, ErrFrameTooLarge
	}

	// write length
	n, _ := fr.w.Write([]byte{byte(length >> 16), byte(length >> 8), byte(length)})
	// write nonce and data
	m, err := fr.w.Write(p)

	if err == nil && (n+m != length+frameHeaderLen) {
		err = io.ErrShortWrite
	}

	return n + m, err
}

// FrameHeader is the common header for our message format
// +--------------------------+
// | Length of data (24 bits) |
// +--------------------------+
// | Nonce (24 bytes)         |
// +----------------------------------+
type FrameHeader struct {
	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// Nonce is used for each message
	Nonce [24]byte
}

func (fh *FrameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	fmt.Fprintf(&buf, " nonce=%q", fh.Nonce)
	fmt.Fprintf(&buf, " len=%d]", fh.Length)
	return buf.String()
}

type stickyErrWriter struct {
	w   io.Writer
	err *error
}

func (sew stickyErrWriter) Write(p []byte) (n int, err error) {
	if *sew.err != nil {
		return 0, *sew.err
	}

	n, err = sew.w.Write(p)
	*sew.err = err
	return
}
