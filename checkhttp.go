package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

func makeTransport(vhost string, timeout time.Duration) http.RoundTripper {
	baseDialFunc := (&net.Dialer{
		Timeout: timeout,
	}).DialContext

	dialFunc := baseDialFunc
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	if vhost != "" {
		servername, _, err := net.SplitHostPort(vhost)
		if err != nil {
			servername = vhost
		}
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         servername,
		}
	}

	return &http.Transport{
		// inherited http.DefaultTransport
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialFunc,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
		// self-customized values
		ResponseHeaderTimeout: timeout,
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     true,
	}
}

func makeHTTPCheckHandler(defaultUA string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if vars["port"] == "" {
			userErrorJSON(w, fmt.Errorf("no Port number Specified"))
			return
		}
		port, err := strconv.Atoi(vars["port"])
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse port number: %v", err))
			return
		}

		if vars["status"] == "" {
			userErrorJSON(w, fmt.Errorf("no Status code Specified"))
			return
		}
		expectedStatus, err := strconv.Atoi(vars["status"])
		if err != nil {
			userErrorJSON(w, fmt.Errorf("could not parse status number: %v", err))
			return
		}

		if vars["method"] == "" {
			userErrorJSON(w, fmt.Errorf("no HTTP method code Specified"))
			return
		}
		method := strings.ToUpper(vars["method"])

		vhost := vars["host"]
		host := net.JoinHostPort(vhost, fmt.Sprintf("%d", port))
		path := vars["path"]
		path = "/" + path

		schema := "http"
		if vars["http_scheme"] == "check_https" {
			schema = "https"
		}
		uri := fmt.Sprintf("%s://%s%s", schema, host, path)
		if r.URL.RawQuery != "" {
			uri += "?" + r.URL.RawQuery
		}

		println(uri)
		ctx, cancel := context.WithTimeout(r.Context(), mainTimeout)
		defer cancel()

		var b bytes.Buffer
		req, err := http.NewRequestWithContext(
			ctx,
			method,
			uri,
			&b,
		)
		if err != nil {
			userErrorJSON(w, fmt.Errorf("failed create request: %v", err))
			return
		}
		ua := r.UserAgent()
		if ua == "" {
			ua = defaultUA
		}
		req.Header.Set("User-Agent", ua)

		transport := makeTransport(vars["host"], mainTimeout)
		client := &http.Client{
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		start := time.Now()
		res, err := client.Do(req)
		duration := time.Since(start)

		if err != nil {
			outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), err)
			return
		}

		defer func() { _ = res.Body.Close() }()
		_, _ = io.Copy(io.Discard, res.Body)
		if res.StatusCode != expectedStatus {
			outJSON(w, CRITICAL, fmt.Sprintf("duration:%f", duration.Seconds()), fmt.Errorf("status code %d not match %d", res.StatusCode, expectedStatus))
			return
		}

		outJSON(w, OK, fmt.Sprintf("duration:%f", duration.Seconds()))
	}
}
