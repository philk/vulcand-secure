package secure

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/codegangsta/cli"
	"github.com/mailgun/vulcand/Godeps/_workspace/src/github.com/mailgun/oxy/testutils"
	. "github.com/mailgun/vulcand/Godeps/_workspace/src/gopkg.in/check.v1"
	"github.com/mailgun/vulcand/plugin"
	"github.com/unrolled/secure"
)

func TestCL(t *testing.T) { TestingT(t) }

type SecureSuite struct{}

var _ = Suite(&SecureSuite{})

func (s *SecureSuite) TestSpecIsOK(c *C) {
	c.Assert(plugin.NewRegistry().AddSpec(GetSpec()), IsNil)
}

func (s *SecureSuite) TestSecureFromCli(c *C) {
	app := cli.NewApp()
	app.Name = "secure_test"
	executed := false
	app.Action = func(ctx *cli.Context) {
		executed = true
		out, err := FromCli(ctx)
		c.Assert(out, NotNil)
		c.Assert(err, IsNil)

		m := out.(*SecureMiddleware)
		c.Assert(m.Opts.BrowserXssFilter, Equals, true)
	}
	app.Flags = CliFlags()
	app.Run([]string{"secure_test", "--xss-filter"})
	c.Assert(executed, Equals, true)
}

func (s *SecureSuite) TestRequests(c *C) {
	m, err := New(secure.Options{
		SSLRedirect:        true,
		SSLProxyHeaders:    map[string]string{"X-Forwarded-Proto": "https"},
		ContentTypeNosniff: true,
		BrowserXssFilter:   true,
	})
	c.Assert(err, IsNil)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "testing")
	})

	sm, err := m.NewHandler(h)
	c.Assert(err, IsNil)

	srv := httptest.NewServer(sm)
	defer srv.Close()

	// http request triggers 301
	re, _, err := testutils.Get(srv.URL)
	c.Assert(err, NotNil)
	c.Assert(re.StatusCode, Equals, http.StatusMovedPermanently)

	// X-Forwarded-Proto: https doesn't trigger 301
	re, _, err = testutils.Get(srv.URL, testutils.Header("X-Forwarded-Proto", "https"))
	c.Assert(err, IsNil)
	c.Assert(re.StatusCode, Equals, http.StatusOK)
	c.Assert(re.Header["X-Content-Type-Options"], NotNil)
	c.Assert(re.Header["X-Content-Type-Options"][0], Equals, "nosniff")
	c.Assert(re.Header["X-Xss-Protection"], NotNil)
	c.Assert(re.Header["X-Xss-Protection"][0], Equals, "1; mode=block")
}
