package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	ping "github.com/digineo/go-ping"
	"github.com/gorilla/mux"
)

type pinger interface {
	Ping(destination *net.IPAddr, timeout time.Duration) (time.Duration, error)
}

type probeResult struct {
	rtts      []float64
	successes int
	failures  int
	totalRTT  float64
	errs      []error
}

// probePing runs up to count pings against ip, sleeping interval between
// attempts. It returns when either all pings finish or ctx is cancelled.
// The worker goroutine always finishes before probePing returns, so callers
// may safely close the pinger right after.
func probePing(ctx context.Context, p pinger, ip *net.IPAddr, count int, interval, timeout time.Duration) probeResult {
	resultCh := make(chan probeResult, 1)
	go func() {
		var r probeResult
		for i := range count {
			if ctx.Err() != nil {
				break
			}
			if i > 0 {
				t := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					t.Stop()
					resultCh <- r
					return
				case <-t.C:
				}
			}
			rtt, err := p.Ping(ip, timeout)
			if err != nil {
				r.errs = append(r.errs, err)
				r.failures++
				continue
			}
			ms := float64(rtt.Nanoseconds()) / 1000.0 / 1000.0
			r.rtts = append(r.rtts, ms)
			r.totalRTT += ms
			r.successes++
		}
		resultCh <- r
	}()

	r := <-resultCh
	if ctx.Err() != nil {
		r.errs = append(r.errs, fmt.Errorf("reached timeout: %v", ctx.Err()))
	}
	return r
}

func handleCheckPing(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	mainTimeout := monTimeout
	if r.Header.Get("X-Timeout") != "" {
		i, err := strconv.ParseInt(r.Header.Get("X-Timeout"), 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse X-Timeout: %v", err))
			return
		}
		mainTimeout = time.Second * time.Duration(i)
	}

	if vars["ip"] == "" {
		userErrorJSON(w, fmt.Errorf("no IP Address Specified"))
		return
	}
	count := 1
	if vars["count"] != "" {
		var err error
		count, err = strconv.Atoi(vars["count"])
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse count: %v", err))
			return
		}
	}
	interval := pingInterval
	if vars["interval"] != "" {
		var err error
		i, err := strconv.ParseInt(vars["interval"], 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse interval: %v", err))
			return
		}
		interval = time.Millisecond * time.Duration(i)
	}

	timeout := pingTimeout
	if vars["timeout"] != "" {
		var err error
		i, err := strconv.ParseInt(vars["timeout"], 10, 64)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse timeout: %v", err))
			return
		}
		timeout = time.Millisecond * time.Duration(i)
	}

	ip, err := parseIP(vars["ip"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("could not parse IP: %v", err))
		return
	}
	var p *ping.Pinger
	if strings.Contains(ip.String(), ":") {
		p, err = ping.New("", "::")
		if err != nil {
			outJSON(w, CRITICAL, "", fmt.Errorf("could not create pinger: %v", err))
			return
		}
	} else {
		p, err = ping.New("0.0.0.0", "")
		if err != nil {
			outJSON(w, CRITICAL, "", fmt.Errorf("could not create pinger: %v", err))
			return
		}
	}

	defer p.Close()

	ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
	defer cancel()

	result := probePing(ctx, p, ip, count, interval, timeout)

	rtts := sort.Float64Slice(result.rtts)
	sort.Sort(rtts)
	msgs := make([]string, 0)
	msgs = append(msgs, fmt.Sprintf("success:%d", result.successes))
	msgs = append(msgs, fmt.Sprintf("error:%d", result.failures))
	if result.successes > 0 {
		msgs = append(msgs, fmt.Sprintf("max:%f", rtts[round(float64(result.successes))]))
		msgs = append(msgs, fmt.Sprintf("average:%f", result.totalRTT/float64(result.successes)))
		msgs = append(msgs, fmt.Sprintf("90_percentile:%f", rtts[round(float64(result.successes)*0.90)]))
	}
	code := OK
	if result.successes == 0 {
		code = CRITICAL
	} else if result.failures > 0 {
		code = WARNING
	}
	outJSON(w, code, strings.Join(msgs, ","), result.errs...)
}
