// Package fetch downloads files over HTTPS, whole or by byte ranges.
package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var client = &http.Client{Timeout: 5 * time.Minute}

// ErrNotFound is the error of a download the server has no file for.
var ErrNotFound = errors.New("not found")

// Bytes downloads url, refusing bodies larger than limit.
func Bytes(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("GET %s: %w", url, ErrNotFound)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: body exceeds %d bytes", url, limit)
	}
	return b, nil
}

const blockSize = 64 << 10

// RangeReader is an io.ReaderAt over a remote file that fetches aligned
// 64 KiB blocks with HTTP range requests and keeps them in memory.
type RangeReader struct {
	ctx  context.Context
	url  string
	size int64

	mu     sync.Mutex
	blocks map[int64][]byte
	// Fetched counts downloaded bytes.
	Fetched int64
}

// NewRangeReader checks that the server honors range requests and records
// the file size.
func NewRangeReader(ctx context.Context, url string) (*RangeReader, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HEAD %s: %s", url, resp.Status)
	}
	if resp.Header.Get("Accept-Ranges") != "bytes" {
		return nil, fmt.Errorf("HEAD %s: server does not accept byte ranges", url)
	}
	size, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)
	if err != nil || size <= 0 {
		return nil, fmt.Errorf("HEAD %s: no usable Content-Length", url)
	}
	return &RangeReader{ctx: ctx, url: url, size: size, blocks: make(map[int64][]byte)}, nil
}

// Size is the remote file size.
func (r *RangeReader) Size() int64 { return r.size }

func (r *RangeReader) block(index int64) ([]byte, error) {
	r.mu.Lock()
	b, ok := r.blocks[index]
	r.mu.Unlock()
	if ok {
		return b, nil
	}
	start := index * blockSize
	end := min(start+blockSize, r.size) - 1
	req, err := http.NewRequestWithContext(r.ctx, http.MethodGet, r.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, end))
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent {
		return nil, fmt.Errorf("GET %s bytes %d-%d: %s", r.url, start, end, resp.Status)
	}
	b, err = io.ReadAll(io.LimitReader(resp.Body, blockSize+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s bytes %d-%d: %w", r.url, start, end, err)
	}
	if int64(len(b)) != end-start+1 {
		return nil, fmt.Errorf("GET %s bytes %d-%d: got %d bytes", r.url, start, end, len(b))
	}
	r.mu.Lock()
	r.blocks[index] = b
	r.Fetched += int64(len(b))
	r.mu.Unlock()
	return b, nil
}

// ReadAt implements io.ReaderAt.
func (r *RangeReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset %d", off)
	}
	n := 0
	for n < len(p) {
		pos := off + int64(n)
		if pos >= r.size {
			return n, io.EOF
		}
		b, err := r.block(pos / blockSize)
		if err != nil {
			return n, err
		}
		n += copy(p[n:], b[pos%blockSize:])
	}
	return n, nil
}
