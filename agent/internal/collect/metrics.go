// Package collect reads basic host metrics from /proc and statfs (SPEC §8.4).
package collect

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type Snapshot struct {
	CPUPct    float64
	MemPct    float64
	DiskPct   float64
	Load1     float64
	UptimeSec int64
}

type CPUSampler struct{ prevIdle, prevTotal uint64 }

// CPUPct returns usage since the previous call (0 on the first call).
func (s *CPUSampler) CPUPct() float64 {
	idle, total, err := readCPU()
	if err != nil {
		return 0
	}
	defer func() { s.prevIdle, s.prevTotal = idle, total }()
	if s.prevTotal == 0 || total <= s.prevTotal {
		return 0
	}
	dIdle, dTotal := float64(idle-s.prevIdle), float64(total-s.prevTotal)
	return round1(100 * (1 - dIdle/dTotal))
}

func Take(s *CPUSampler) Snapshot {
	return Snapshot{
		CPUPct:    s.CPUPct(),
		MemPct:    memPct(),
		DiskPct:   diskPct("/"),
		Load1:     load1(),
		UptimeSec: uptime(),
	}
}

func (s Snapshot) Attrs() map[string]string {
	return map[string]string{
		"cpuPct":    fmt.Sprint(s.CPUPct),
		"memPct":    fmt.Sprint(s.MemPct),
		"diskPct":   fmt.Sprint(s.DiskPct),
		"load1":     fmt.Sprint(s.Load1),
		"uptimeSec": fmt.Sprint(s.UptimeSec),
	}
}

func readCPU() (idle, total uint64, err error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, fmt.Errorf("empty /proc/stat")
	}
	fields := strings.Fields(sc.Text())[1:]
	for i, v := range fields {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return idle, total, nil
}

func memPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total, avail float64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(parts[1], 64)
		switch parts[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 {
		return 0
	}
	return round1(100 * (1 - avail/total))
}

func diskPct(path string) float64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0
	}
	used := float64(st.Blocks-st.Bfree) / float64(st.Blocks-st.Bfree+st.Bavail)
	return round1(100 * used)
}

func load1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return v
}

func uptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return int64(v)
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }
