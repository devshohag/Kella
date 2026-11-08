// Package tail follows a log file like `tail -F`: starts at the end, survives rotation and truncation.
package tail

import (
	"bufio"
	"context"
	"io"
	"os"
	"syscall"
	"time"
)

// Follow sends each new line of path to out until ctx is cancelled. Missing files are retried.
func Follow(ctx context.Context, path string, out chan<- string) {
	var (
		f      *os.File
		r      *bufio.Reader
		inode  uint64
		offset int64
	)
	open := func(seekEnd bool) bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		if seekEnd {
			offset, _ = nf.Seek(0, io.SeekEnd)
		} else {
			offset = 0
		}
		if f != nil {
			f.Close()
		}
		f, r, inode = nf, bufio.NewReader(nf), inodeOf(path)
		return true
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	opened := open(true)
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	partial := ""

	for {
		if opened {
			for {
				line, err := r.ReadString('\n')
				offset += int64(len(line))
				if err != nil {
					partial += line
					break
				}
				select {
				case out <- partial + line[:len(line)-1]:
				case <-ctx.Done():
					return
				}
				partial = ""
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}

		if !opened {
			opened = open(false)
			continue
		}
		// Rotation: the path now points to a different file. Truncation: file got smaller.
		if inodeOf(path) != inode {
			opened = open(false)
			partial = ""
		} else if st, err := f.Stat(); err == nil && st.Size() < offset {
			opened = open(false)
			partial = ""
		}
	}
}

func inodeOf(path string) uint64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}
