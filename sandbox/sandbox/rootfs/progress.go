//go:build linux

package rootfs

import "io"

// ProgressPhase identifies a managed-rootfs provisioning phase.
type ProgressPhase string

const (
	ProgressWaitingForCacheLock ProgressPhase = "waiting for cache lock"
	ProgressValidatingCache     ProgressPhase = "validating cache manifest"
	ProgressDownloadingArchive  ProgressPhase = "downloading and hashing archive"
	ProgressExtractingFiles     ProgressPhase = "extracting files"
	ProgressPublishingCache     ProgressPhase = "publishing cache"
)

// ProgressEvent reports synchronous managed-rootfs provisioning progress.
// Current is a byte count for byte-oriented phases. Total is the final HTTP
// response Content-Length when it is positive, or zero when it is unknown.
type ProgressEvent struct {
	Phase   ProgressPhase
	Current int64
	Total   int64
}

// ProgressFunc receives managed-rootfs progress events synchronously.
type ProgressFunc func(ProgressEvent)

func (p Provisioner) reportProgress(event ProgressEvent) {
	if p.Progress != nil {
		p.Progress(event)
	}
}

type progressReader struct {
	reader  io.Reader
	current int64
	report  func(int64)
}

func (r *progressReader) Read(buffer []byte) (int, error) {
	n, err := r.reader.Read(buffer)
	if n > 0 {
		r.current += int64(n)
		r.report(r.current)
	}
	return n, err
}

type progressWriter struct {
	writer  io.Writer
	current int64
	report  func(int64)
}

func (w *progressWriter) Write(buffer []byte) (int, error) {
	n, err := w.writer.Write(buffer)
	if n > 0 {
		w.current += int64(n)
		w.report(w.current)
	}
	return n, err
}
