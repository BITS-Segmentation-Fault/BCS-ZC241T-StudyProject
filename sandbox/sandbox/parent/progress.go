//go:build linux

package parent

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"sandbox/sandbox/rootfs"
)

const progressRedrawInterval = 100 * time.Millisecond

type progressRenderer struct {
	out    io.Writer
	tty    bool
	last   time.Time
	phase  rootfs.ProgressPhase
	total  int64
	active bool
}

func newProgressRenderer(file *os.File) *progressRenderer {
	renderer := &progressRenderer{out: file}
	if file != nil {
		_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
		renderer.tty = err == nil
	}
	return renderer
}

func (r *progressRenderer) report(event rootfs.ProgressEvent) {
	if r == nil || !r.tty || r.out == nil {
		return
	}
	now := time.Now()
	if r.active && r.phase == event.Phase && r.total == event.Total && now.Sub(r.last) < progressRedrawInterval && event.Current != event.Total {
		return
	}
	r.last = now
	r.phase = event.Phase
	r.total = event.Total
	r.active = true
	if event.Phase == rootfs.ProgressDownloadingArchive && event.Total > 0 {
		percent := progressPercent(event.Current, event.Total)
		fmt.Fprintf(r.out, "\r\033[K%s %s %3d%% %s/%s", event.Phase, progressBar(event.Current, event.Total), percent, formatBytes(event.Current), formatBytes(event.Total))
		return
	}
	if event.Current > 0 {
		fmt.Fprintf(r.out, "\r\033[K%s %s", event.Phase, formatBytes(event.Current))
		return
	}
	fmt.Fprintf(r.out, "\r\033[K%s", event.Phase)
}

const progressBarWidth = 20

func progressPercent(current, total int64) int {
	if total <= 0 || current <= 0 {
		return 0
	}
	if current >= total {
		return 100
	}
	return int(float64(current) / float64(total) * 100)
}

func progressBar(current, total int64) string {
	if total <= 0 || current <= 0 {
		return "[>" + strings.Repeat(".", progressBarWidth-1) + "]"
	}
	if current >= total {
		return "[" + strings.Repeat("=", progressBarWidth) + "]"
	}
	filled := int(float64(current) / float64(total) * progressBarWidth)
	if filled < 1 {
		filled = 1
	}
	return "[" + strings.Repeat("=", filled) + ">" + strings.Repeat(".", progressBarWidth-filled-1) + "]"
}

func (r *progressRenderer) finish() {
	if r == nil || !r.tty || !r.active || r.out == nil {
		return
	}
	fmt.Fprint(r.out, "\r\033[K\n")
	r.active = false
}

func formatBytes(value int64) string {
	if value < 1024 {
		return fmt.Sprintf("%d B", value)
	}
	if value < 1024*1024 {
		return fmt.Sprintf("%.1f KiB", float64(value)/1024)
	}
	if value < 1024*1024*1024 {
		return fmt.Sprintf("%.1f MiB", float64(value)/(1024*1024))
	}
	return fmt.Sprintf("%.1f GiB", float64(value)/(1024*1024*1024))
}
