package main

import "testing"

func TestApexes(t *testing.T) {
	cases := []struct {
		in       string
		expected string
	}{
		// plain ICANN suffixes
		{"sub.example.com", "example.com"},
		{"example.com", "example.com"},
		{"test.google.co.uk", "google.co.uk"},
		{"a.b.c.example.com.au", "example.com.au"},
		{"https://user:pass@sub.example.co.uk:8443/p?q=1#f", "example.co.uk"},
		{"SUB.EXAMPLE.COM", "example.com"},

		// private suffixes are honoured: shared hosting / CDN hostnames are
		// their own apex so the provider's domain never lands in scope
		{"skydo-documents.s3.ap-south-1.amazonaws.com", "skydo-documents.s3.ap-south-1.amazonaws.com"},
		{"backoffice.clerk.app", "backoffice.clerk.app"},
		{"dl.pstmn.io", "dl.pstmn.io"},
		{"fbcdn-a.akamaihd.net", "fbcdn-a.akamaihd.net"},
		{"foo.github.io", "foo.github.io"},
		{"a.b.foo.github.io", "foo.github.io"},
		{"x.com.github.io", "com.github.io"},

		// a hostname that is itself a private suffix is still an apex
		{"brave.app", "brave.app"},
		{"brave.dev", "brave.dev"},
		{"int.apple", "int.apple"},
		{"github.io", "github.io"},
		{"www.github.io", "www.github.io"},
		{"s3.ap-south-1.amazonaws.com", "s3.ap-south-1.amazonaws.com"},
		{"S3.AP-SOUTH-1.AMAZONAWS.COM.", "s3.ap-south-1.amazonaws.com"},
		{"uk.com", "uk.com"},
		{"www.quipelements.com", "www.quipelements.com"},
		{"a.www.quipelements.com", "a.www.quipelements.com"},
		{"x.y.a.www.quipelements.com", "a.www.quipelements.com"},

		// CentralNic-style zones stay registrable
		{"walmart.com.ru", "walmart.com.ru"},
		{"a.b.walmart.com.ru", "walmart.com.ru"},
		{"salesforce.uk.com", "salesforce.uk.com"},
		{"workday.jpn.com", "workday.jpn.com"},
		{"tesco-bank.uk.net", "tesco-bank.uk.net"},
		{"hackerone.co.nl", "hackerone.co.nl"},
		{"uber.com.de", "uber.com.de"},
		{"skyscanner.co.com", "skyscanner.co.com"},

		// com/co/net/org on a ccTLD, even when the PSL doesn't list it
		{"bmw-motorrad.com.cr", "bmw-motorrad.com.cr"},
		{"www.bmw-motorrad.com.at", "bmw-motorrad.com.at"},
		{"bmw-motorrad.com.co.uk", "bmw-motorrad.com.co.uk"},
		{"bmw-motorrad.com.co.id", "bmw-motorrad.com.co.id"},
		{"bmw-motorrad.com.za", "bmw-motorrad.com.za"},
		{"bmw-motorrad.com.uk", "bmw-motorrad.com.uk"},
		{"x.net.cr", "x.net.cr"},
		{"com.cr", "com.cr"},
		{"www.ge.com", "ge.com"},
		{"www.co.com", "www.co.com"},

		// suffixes dropped from the PSL but still in use
		{"amazon.ac.tj", "amazon.ac.tj"},
		{"www.amazon.ac.tj", "amazon.ac.tj"},
		{"x.com.is", "x.com.is"},
		{"x.info.co", "x.info.co"},

		// suffixes only in newer PSL releases
		{"sub.example.co.az", "example.co.az"},
		{"sub.example.com.bd", "example.com.bd"},

		// unknown TLDs fall back to the default "*" rule
		{"com.autoscout24", "com.autoscout24"},
		{"x.com.datacamp", "com.datacamp"},
		{"revolut.junior", "revolut.junior"},

		// trailing dots
		{"xyz.example.com.", "example.com"},
		{"xyz.example.com..", "example.com"},
		{"http://xyz.example.com./path", "example.com"},
		{"bmw-motorrad.com.cr.", "bmw-motorrad.com.cr"},

		// nothing sensible to return
		{"localhost", ""},
		{"com", ""},
		{"co.uk", ""},
		{"co.az", ""},
		{"amazonaws.com", "amazonaws.com"},
		{".", ""},
		{"x.x", ""},
		{"a.b.x.x", ""},
		{"example.a", ""},
		{"example.123", ""},
		{"example.1", ""},
		{"x.xx", "x.xx"},
		{"example.a1", "example.a1"},
		{"com.autoscout24", "com.autoscout24"},
		{"example.xn--p1ai", "example.xn--p1ai"},
		{"127.0.0.1", ""},
		{"http://127.0.0.1:8080/", ""},
		{"http://[::1]/", ""},
	}

	for _, c := range cases {
		u, err := parseURL(c.in)
		if err != nil {
			t.Fatalf("parseURL(%s): %s", c.in, err)
		}
		if have := apexes(u, "")[0]; have != c.expected {
			t.Errorf("apex(%s): want %q, have %q", c.in, c.expected, have)
		}
	}
}

func TestDomainParts(t *testing.T) {
	cases := []struct {
		in, sub, root, tld string
	}{
		{"www.bmw-motorrad.com.cr", "www", "bmw-motorrad", "com.cr"},
		{"a.b.example.co.uk", "a.b", "example", "co.uk"},
		{"xyz.example.com.", "xyz", "example", "com"},
		{"x.y.walmart.com.ru", "x.y", "walmart", "com.ru"},
	}
	for _, c := range cases {
		u, _ := parseURL(c.in)
		got := format(u, "%S|%r|%t")[0]
		if want := c.sub + "|" + c.root + "|" + c.tld; got != want {
			t.Errorf("parts(%s): want %q, have %q", c.in, want, got)
		}
	}
}

func TestParseURLHost(t *testing.T) {
	cases := []struct {
		in, host, port string
	}{
		{"example.com", "example.com", ""},
		{"example.com:8443", "example.com", "8443"},
		{"sub.example.com:8443/a?b=c", "sub.example.com", "8443"},
		{"user:pass@example.com", "example.com", ""},
		{"user:p%40ss@example.com:8080/x", "example.com", "8080"},
		{"https://example.com:8443/", "example.com", "8443"},
		{"//example.com/a", "example.com", ""},
		{"[::1]:80", "::1", "80"},
		{"xyz.example.com.:443", "xyz.example.com.", "443"},
	}
	for _, c := range cases {
		u, err := parseURL(c.in)
		if err != nil {
			t.Errorf("parseURL(%s): %s", c.in, err)
			continue
		}
		if u.Hostname() != c.host || u.Port() != c.port {
			t.Errorf("parseURL(%s): want %s/%s, have %s/%s", c.in, c.host, c.port, u.Hostname(), u.Port())
		}
	}

	// schemes that aren't host based must not grow a bogus host
	for _, in := range []string{"javascript:alert(1)", "data:text/html,hi"} {
		if u, err := parseURL(in); err == nil && u.Host != "" {
			t.Errorf("parseURL(%s): unexpected host %q", in, u.Host)
		}
	}
}
