package main

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
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ProxyRedirection
type ProxyRedirection struct {
	hostname string
	regexps  []*regexp.Regexp
}

var askWisprHTML = `<html><body><!-- <?xml version="1.0" encoding="UTF-8"?> <WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/
XMLSchema-instance" xsi:noNamespaceSchemaLocation="WISPAccessGatewayParam.xsd"> <Redirect> <MessageType>100</MessageType> <ResponseCode>0<
/ResponseCode> <AccessProcedure>1.0</AccessProcedure> <LocationName>Quebec Open Access</LocationName> <ReplyMessage>Welcome</ReplyMessage>
 <AccessLocation>BackEnd Remote Login</AccessLocation> <LoginURL>http://login.wifi/</LoginURL> <AbortLoginURL>http://fail.wifi</AbortLo
ginURL> </Redirect> </WISPAccessGatewayParam> --></body></html>`

var okWispHTML = `<html><body><!-- <?xml version="1.0" encoding="UTF-8"?> <WISPAccessGatewayParam xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:
noNamespaceSchemaLocation="WISPAccessGatewayParam.xsd"> <AuthenticationReply> <MessageType>120</MessageType> <ResponseCode>50</ResponseCod
e> <AccessProcedure>1.0</AccessProcedure> <ReplyMessage>Authentication Success</ReplyMessage> <LogoffURL>http://home.wifi/</LogoffURL> </
AuthenticationReply> </WISPAccessGatewayParam> --></body></html>`

var noaccessHTML = `<html><body>You don't have access <a href="http://login.wifi?key=%s">please login here</a></body></html>`

func NewProxyRedirection(h string, regexps ...string) *ProxyRedirection {
	p := &ProxyRedirection{
		hostname: h,
		regexps:  make([]*regexp.Regexp, len(regexps)),
	}
	for i, r := range regexps {
		p.regexps[i] = regexp.MustCompile(r)
	}
	return p
}

func (p *ProxyRedirection) Match(str string) (string, bool) {
	for _, r := range p.regexps {
		if r.Match([]byte(str)) {
			return p.hostname, true
		}
	}
	return "", false
}

type WisprProxy struct {
	rules      []*ProxyRedirection
	appleRules *ProxyRedirection
	hosts      map[string]time.Time
	pKey       []byte
	sync.RWMutex
}

func NewWisprProxy(ph ...*ProxyRedirection) *WisprProxy {
	// generate a private key
	rand.Seed(time.Now().UTC().UnixNano())
	bytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		bytes[i] = byte(rand.Intn(256))
	}

	w := &WisprProxy{
		rules: ph,
		pKey:  bytes,
		hosts: make(map[string]time.Time),
		appleRules: NewProxyRedirection("apple",
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
	h := make(http.Header)
	h["Content-Type"] = []string{"text/html"}

	res := &http.Response{
		Header:     h,
		Request:    r,
		StatusCode: http.StatusOK,
	}

	// checking against apple known hosts
	if _, ok := w.appleRules.Match(r.Host); ok {
		// check for the User Agent
		if strings.HasPrefix(r.Header.Get("User-Agent"), "CaptiveNetworkSupport") {
			// it's a match
			if w.IsAllowed(from) {
				res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(okWispHTML)))
				log.Println("Wispr request sent to", from)
			} else {
				res.Body = ioutil.NopCloser(bytes.NewBuffer([]byte(askWisprHTML)))
				log.Println("Wispr ok sent to", from)
			}
			return res, nil
		}
	}
	if w.IsAllowed(from) {
		return http.DefaultTransport.RoundTrip(r)
	}

	sha := w.genKeyForHost(from)
	// User GET the login page check for the key
	if r.Host == "login.wifi" {
		log.Println(r.URL.Query().Get("key"))
		if r.URL.Query().Get("key") == sha {
			w.Allow(from)
			log.Println("allowed", from)
			res.StatusCode = http.StatusFound
			res.Header.Set("Location", "http://home.wifi")
			redirectBody := bytes.NewBuffer([]byte(`<html><body>Redirected to <a href="http://home.wifi">Home</a></body></html>`))
			res.Body = ioutil.NopCloser(redirectBody)
			return res, nil
		}
	}

	html := fmt.Sprintf(noaccessHTML, url.QueryEscape(sha))
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

func main() {
	yahoo := NewProxyRedirection("www.google.com", `(?i)yahoo\.com/.*`)
	wproxy := NewWisprProxy(yahoo)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		wproxy.ServeHTTP(w, r)
	})
	log.Fatal(http.ListenAndServe(":8181", nil))
}
