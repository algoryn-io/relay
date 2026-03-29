package listener

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

type Listener struct {
	HTTP  *http.Server
	HTTPS *http.Server
}

type Options struct {
	HTTPPort      int
	HTTPSPort     int
	TLSMode       string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	IdleTimeout   time.Duration
	HeaderTimeout time.Duration
}

func New(opts Options, handler http.Handler) *Listener {
	httpAddr := ":" + strconv.Itoa(opts.HTTPPort)
	httpsAddr := ":" + strconv.Itoa(opts.HTTPSPort)

	return &Listener{
		HTTP: &http.Server{
			Addr:              httpAddr,
			Handler:           handler,
			ReadTimeout:       opts.ReadTimeout,
			WriteTimeout:      opts.WriteTimeout,
			IdleTimeout:       opts.IdleTimeout,
			ReadHeaderTimeout: opts.HeaderTimeout,
		},
		HTTPS: &http.Server{
			Addr:              httpsAddr,
			Handler:           handler,
			ReadTimeout:       opts.ReadTimeout,
			WriteTimeout:      opts.WriteTimeout,
			IdleTimeout:       opts.IdleTimeout,
			ReadHeaderTimeout: opts.HeaderTimeout,
		},
	}
}

func (l *Listener) Start(ctx context.Context) error {
	_ = ctx
	// TODO: implement HTTP and optional HTTPS startup with graceful error propagation.
	return nil
}

func (l *Listener) Shutdown(ctx context.Context) error {
	if l.HTTP != nil {
		_ = l.HTTP.Shutdown(ctx)
	}
	if l.HTTPS != nil {
		_ = l.HTTPS.Shutdown(ctx)
	}
	// TODO: aggregate and return shutdown errors for HTTP/HTTPS servers.
	return nil
}
