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

	wbuf   []byte
	unread []byte
}

// NewFramer returns a Framer that writes frames to w and reads them from r.
func NewFramer(w io.Writer, r io.Reader) *Framer {
	fr := &Framer{
		w: w,
		r: r,
	}
	fr.getReadBuf = func(size uint32) []byte {
		if cap(fr.readBuf) >= int(size) {
			return fr.readBuf[:size]
		}
		fr.readBuf = make([]byte, size)
		return fr.readBuf
	}
	return fr
}

func (fr *Framer) HasUnreadPortion() bool {
	return fr.unread != nil
}

func (fr *Framer) ReadPayload(p []byte) (int, error) {
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
	} else {
		// We need to buffer the read of this message - provided buffer is too small to hold the entire message
		copy(p, fr.unread[:dstLen])
		fr.unread = fr.unread[dstLen:]
		return dstLen, nil
	}
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
func (fr *Framer) ReadFrameHeader(r io.Reader) (frameHeader, error) {
	bufp := fhBytes.Get().(*[]byte)
	defer fhBytes.Put(bufp)
	return readFrameHeader(*bufp, r)
}

func readFrameHeader(buf []byte, r io.Reader) (frameHeader, error) {
	if _, err := io.ReadFull(r, buf[:frameHeaderLen]); err != nil {
		return frameHeader{}, err
	}

	var nonce [24]byte

	copy(nonce[:], buf[3:frameHeaderLen])

	return frameHeader{
		Length: (uint32(buf[0])<<16 | uint32(buf[1])<<8 | uint32(buf[2])),
		Nonce:  nonce,
	}, nil
}

func (fr *Framer) Write(p []byte) (int, error) {
	// write the nonce and data
	fr.startWrite()
	fr.writeBytes(p)
	// wrote nonce, data and length bytes
	return len(p) + 3, fr.endWrite()
}

func (fr *Framer) writeBytes(p []byte) {
	fr.wbuf = append(fr.wbuf, p...)
}

func (fr *Framer) startWrite() {
	fr.wbuf = append(fr.wbuf[:0],
		0,
		0,
		0)
}

func (fr *Framer) endWrite() error {
	// Now that we know the final size, fill in the FrameHeader in
	// the space previously reserved for it. Abuse append.
	length := len(fr.wbuf) - frameHeaderLen
	if length >= (1 << 24) {
		return ErrFrameTooLarge
	}
	_ = append(fr.wbuf[:0],
		byte(length>>16),
		byte(length>>8),
		byte(length))
	n, err := fr.w.Write(fr.wbuf)
	if err == nil && n != len(fr.wbuf) {
		err = io.ErrShortWrite
	}
	return err
}

type frameHeader struct {
	// Length is the length of the frame, not including the 9 byte header.
	// The maximum size is one byte less than 16MB (uint24), but only
	// frames up to 16KB are allowed without peer agreement.
	Length uint32

	// Nonce is used for each message
	Nonce [24]byte
}

func (fh *frameHeader) String() string {
	var buf bytes.Buffer
	buf.WriteString("[FrameHeader ")
	fmt.Fprintf(&buf, " nonce=%q", fh.Nonce)
	fmt.Fprintf(&buf, " len=%d]", fh.Length)
	return buf.String()
}
