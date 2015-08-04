WisprGo
=======

WisprGo is a set of tools to provide a wifi AP with Wispr functionalities, to make it simple Wispr is the protocol that show you a popup when you are entering a free wifi provider (Starbucks, McDonalds ...).  
We need this popup to redirect the user to a page showing it works, cause mostly all the traffic is now secure HTTP there is no way to intercept the calls with the right certificate, so the user may think your AP isn't working.

WisprGo isn't dedicated to provide security, the main goal is to provide a free wifi access portal with popup and without password, but it can be extended to do so.  
The Wispr protocol and the way manufacturers test the connection and display this popup are largely undocumented, I hope we can collect those for this project.

WisprGo comes with a command line tool: `wisprproxy` that you can run on your network, it can replace Nginx as a webserver, reverse proxy server & Wispr proxy.

### Status
The current version so far, displays a popup on iOS, No popup for Android yet but still intercept all the traffics and display a login page.  
It's a **work in progess** further enhancements are coming, like choosing the redirections URLs & customizing the pages, I'm releasing it early to get some help with Android and Microsoft harware.

### Usage
```
wproxy := wisprgo.NewWisprProxy()
wproxy.AddReverseProxyRule("www.google.com", `(?i)yahoo\.com/.*`)
wproxy.AddReverseProxyRule("localhost:8000", `(?i)wikipedia.wifi`)
wproxy.AddFileServer("/tmp", "home.wifi")

http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    wproxy.ServeHTTP(w, r)
})
log.Fatal(http.ListenAndServe(":80", nil))
```
This will create a reverse proxy server on port 80, that:
* reverse proxy all traffic from *yahoo.com to www.google.com
* reverse proxy all traffic for wikipedia.wifi to localhost on port 8000
* serves the website home.wifi from the pages in /tmp
* catch all the traffic coming through it and display a login page to any users who has not click on the submit button.

### Network
For `wisprproxy` to work you have to redirect all traffic through it.  
No need for NAT nor routing just set up a dnsmasq with a wildcard domain:  
`address=/#/10.4.0.1`

An example configuration is explained on [this blog post](http://blog.nobugware.com/post/2015/internet_access_power_outage_disaster_free/).

