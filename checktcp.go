package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// newTCPDialer builds the dialer used for TCP reachability probes. Keep
// dialer.Timeout in sync with the per-request mainTimeout so X-Timeout
// values larger than monTimeout are honored.
func newTCPDialer(mainTimeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: mainTimeout}
}

func handleCheckTCP(w http.ResponseWriter, r *http.Request) {
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
	if vars["port"] == "" {
		userErrorJSON(w, fmt.Errorf("no Port number Specified"))
		return
	}
	port, err := strconv.Atoi(vars["port"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("could not parse port number: %v", err))
		return
	}

	ip, err := parseIP(vars["ip"])
	if err != nil {
		userErrorJSON(w, fmt.Errorf("could not parse IP: %v", err))
		return
	}

	host := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	network := "tcp4"
	if strings.Contains(ip.String(), ":") {
		network = "tcp6"
	}
	ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
	defer cancel()
	dialer := newTCPDialer(mainTimeout)
	start := time.Now()
	conn, err := dialer.DialContext(ctx, network, host)
	duration := time.Since(start)

	if err != nil {
		outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
		return
	}
	defer func() { _ = conn.Close() }()
	outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
}
