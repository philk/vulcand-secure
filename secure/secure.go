package secure

import (
	"fmt"
	"net/http"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/log"
	"github.com/mailgun/vulcand/plugin"
	"github.com/unrolled/secure"
)

// Type is used by vulcan for naming
const Type = "secure"

// GetSpec describes the plugin for vctl
func GetSpec() *plugin.MiddlewareSpec {
	return &plugin.MiddlewareSpec{
		Type:      Type,       // A short name for the middleware
		FromOther: FromOther,  // Tells vulcand how to create middleware from another one
		FromCli:   FromCli,    // Tells vulcand how to create middleware from CLI
		CliFlags:  CliFlags(), // Vulcand will add this flags CLI command
	}
}

// SecureMiddleware stores the configuration
type SecureMiddleware struct {
	Opts secure.Options
}

// SecureHandler describes the http.Handler
type SecureHandler struct {
	cfg  SecureMiddleware
	s    *secure.Secure
	next http.Handler
}

// New returns a new instances of the RedirectMiddleware
func New(opts secure.Options) (*SecureMiddleware, error) {
	return &SecureMiddleware{Opts: opts}, nil
}

// FromOther Will be called by Vulcand when engine or API will read the middleware from the serialized format.
// It's important that the signature of the function will be exactly the same, otherwise Vulcand will
// fail to register this middleware.
// The first and the only parameter should be the struct itself, no pointers and other variables.
// Function should return middleware interface and error in case if the parameters are wrong.
func FromOther(c SecureMiddleware) (plugin.Middleware, error) {
	if c.Opts.STSSeconds == 0 {
		log.Warningf("STSSeconds is 0, STS settings disabled")
	}
	return New(c.Opts)
}

func (m *SecureMiddleware) String() string {
	return fmt.Sprintf("%#v", m.Opts)
}

// FromCli constructs the middleware from the command line
func FromCli(c *cli.Context) (plugin.Middleware, error) {
	opts := secure.Options{
		SSLRedirect:           true,
		SSLProxyHeaders:       map[string]string{"X-Forwarded-Proto": "https"},
		STSSeconds:            int64(c.Int("sts-seconds")),
		STSPreload:            c.Bool("sts-preload"),
		FrameDeny:             c.Bool("frame-deny"),
		ContentTypeNosniff:    c.Bool("no-sniff"),
		BrowserXssFilter:      c.Bool("xss-filter"),
		ContentSecurityPolicy: c.String("content-security-policy"),
	}
	return New(opts)
}

// CliFlags will be used by vulcand to construct help and the CLI command for the vctl command
func CliFlags() []cli.Flag {
	return []cli.Flag{
		cli.IntFlag{
			Name:  "sts-seconds",
			Usage: "Seconds to set in STS Header",
		},
		cli.BoolFlag{
			Name:  "sts-preload",
			Usage: "enable STSPreload",
		},
		cli.BoolFlag{
			Name:  "frame-deny",
			Usage: "enable X-Frame-Options: DENY",
		},
		cli.StringFlag{
			Name:  "content-security-policy",
			Usage: "sets the Content-Security-Policy header to a value",
		},
		cli.BoolFlag{
			Name:  "no-sniff",
			Usage: "enable X-Content-Type-Options: nosniff",
		},
		cli.BoolFlag{
			Name:  "xss-filter",
			Usage: "enable X-XSS-Protection: 1, mode=block",
		},
	}
}

// NewHandler is what vulcand uses to create a handler from the middleware config and insert it
// into the chain
func (m *SecureMiddleware) NewHandler(next http.Handler) (http.Handler, error) {
	s := secure.New(m.Opts)
	return &SecureHandler{
		next: next,
		cfg:  *m,
		s:    s,
	}, nil
}

func (rh *SecureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := rh.s.Process(w, r); err != nil {
		log.Warningf("secure middleware: %s", err)
		return
	}
	rh.next.ServeHTTP(w, r)
}
