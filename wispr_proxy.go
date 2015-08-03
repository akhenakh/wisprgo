package wisprgo

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strings"
	"sync"
	"time"
)

type WisprProxy struct {
	rules      []*reverseProxyRule
	appleRules *reverseProxyRule
	hosts      map[string]time.Time
	pKey       []byte
	sync.RWMutex
}

var askWisprHTML = `<html>
<head>
	<meta http-equiv="Cache-control" content="no-cache">
	<meta http-equiv="Pragma" content="no-cache">
</head>
<body>
<!-- 
<?xml version="1.0" encoding="UTF-8"?> 
<WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="WISPAccessGatewayParam.xsd"> 
<Redirect> 
  <MessageType>100</MessageType> 
  <ResponseCode>0</ResponseCode> 
  <AccessProcedure>1.0</AccessProcedure> 
  <LocationName>Wifi Open Access</LocationName> 
  <ReplyMessage>Welcome to this Free Hospot</ReplyMessage>
   <AccessLocation>BackEnd Remote Login</AccessLocation> 
   <LoginURL>http://login.wifi/</LoginURL> 
   <AbortLoginURL>http://fail.wifi</AbortLoginURL> 
 </Redirect> 
 </WISPAccessGatewayParam> 
 --></body></html>`

var successHTML = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2//EN">
<HTML>
<HEAD>
	<TITLE>Success</TITLE>
</HEAD>
<BODY>
Success
</BODY>
</HTML>`

var noaccessHTML = `<html>
<body>You don't have access
<form action="http://auth.wifi/" method="POST">
            <input type="hidden" name="key" value="%s">
            <input type="hidden" name="button" value="Login">
            <input type="submit">
</form>
</body>
</html>`

func NewWisprProxy() *WisprProxy {
	// generate a private key
	rand.Seed(time.Now().UTC().UnixNano())
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bytes[i] = byte(rand.Intn(256))
	}

	w := &WisprProxy{
		pKey:  bytes,
		hosts: make(map[string]time.Time),
		appleRules: newReverseProxyRule("apple",
			`www\.apple\.com`,
			`captive\.apple\.com`,
			`appleiphonecell\.com`,
			`www\.itools\.info`,
			`www\.ibook\.info`,
			`www\.airport\.us`,
			`www\.thinkdifferent\.us`,
		),
	}
	return w
}

func (w *WisprProxy) genKeyForHost(host string) string {
	hasher := sha1.New()
	hasher.Write([]byte(host))
	hasher.Write(w.pKey)
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))
	return sha
}

func (w *WisprProxy) RoundTrip(r *http.Request) (*http.Response, error) {
	from := r.Header.Get("X-Forwarded-For")
	from = strings.Split(from, ",")[0]
	log.Println("received", r.URL.String(), "from", from)
	h := make(http.Header)
	h["Content-Type"] = []string{"text/html"}

	res := &http.Response{
		Header:     h,
		Request:    r,
		StatusCode: http.StatusOK,
	}

	sha := w.genKeyForHost(from)

	// checking against apple known hosts
	if _, ok := w.appleRules.Match(r.Host); ok {
		// check for the User Agent
		if strings.HasPrefix(r.Header.Get("User-Agent"), "CaptiveNetworkSupport") {
			// it's a match
			if w.IsAllowed(from) {
				res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(successHTML)))
				log.Println("Wispr allowed sent to", from)
			} else {
				res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(askWisprHTML)))
				log.Println("Wispr request sent to", from)
			}
			return res, nil
		}
	}

	// User GET the login page check for the key
	if r.Host == "auth.wifi" {
		log.Println(r.FormValue("key"))
		if r.FormValue("key") == sha {
			w.Allow(from)
			log.Println("allowed", from)
			res.StatusCode = http.StatusFound
			res.Header.Set("Location", "http://home.wifi")
			redirectBody := bytes.NewBuffer([]byte(`<html><body>
<!-- 
<?xml version="1.0" encoding="UTF-8"?> 
<WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:noNamespaceSchemaLocation="http://www.acmewisp.com/WISPAccessGatewayParam.xsd"> 
  <AuthenticationReply> 
	<MessageType>140</MessageType> 
	<ResponseCode>50</ResponseCode>
	<LogoffURL>http://home.wifi/</LogoffURL>
  </AuthenticationReply>
</WISPAccessGatewayParam>
-->
				Redirected to <a href="http://home.wifi">Home</a></body></html>`))
			res.Body = ioutil.NopCloser(redirectBody)
			return res, nil
		}
	}

	if r.Host == "home.wifi" && w.IsAllowed(from) {
		homeBody := bytes.NewBuffer([]byte(`<html><body>
<h1>HOME</h1></body></html>`))
		res.Body = ioutil.NopCloser(homeBody)
		return res, nil
	}

	if w.IsAllowed(from) {
		return http.DefaultTransport.RoundTrip(r)
	}

	html := fmt.Sprintf(noaccessHTML, sha)
	res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(html)))
	return res, nil
}

func (w *WisprProxy) IsAllowed(h string) bool {
	w.RLock()
	defer w.RUnlock()

	if _, ok := w.hosts[h]; ok {
		return true
	}

	return false
}

func (w *WisprProxy) Allow(h string) {
	w.Lock()
	defer w.Unlock()

	w.hosts[h] = time.Now()
}

func (w *WisprProxy) Process(sourceReq *http.Request, destReq *http.Request) {
	destReq = sourceReq
	destReq.URL.Scheme = "http"
	destReq.URL.Host = sourceReq.Host
	for _, rule := range w.rules {
		if host, ok := rule.Match(sourceReq.URL.String()); ok {
			destReq.URL.Host = host
		}
	}
}

func (w *WisprProxy) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	director := func(destReq *http.Request) {
		w.Process(r, destReq)
	}
	proxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: w,
	}
	proxy.ServeHTTP(rw, r)
}

func (w *WisprProxy) AddReverseProxyRule(h string, regexps ...string) {
	r := newReverseProxyRule(h, regexps...)
	w.rules = append(w.rules, r)
}

func newReverseProxyRule(h string, regexps ...string) *reverseProxyRule {
	p := &reverseProxyRule{
		hostname: h,
		regexps:  make([]*regexp.Regexp, len(regexps)),
	}
	for i, r := range regexps {
		p.regexps[i] = regexp.MustCompile(r)
	}
	return p
}

// reverseProxyRules
type reverseProxyRule struct {
	hostname string
	regexps  []*regexp.Regexp
}

func (p *reverseProxyRule) Match(str string) (string, bool) {
	for _, r := range p.regexps {
		if r.Match([]byte(str)) {
			return p.hostname, true
		}
	}
	return "", false
}
