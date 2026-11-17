// Copyright (c) The Conn3x Authors
// SPDX-License-Identifier: MPL-2.0

package mail

import (
	"bufio"
	"net"
	"net/textproto"
	"strings"
	"testing"
)

// smtpServer takes one message on loopback, without STARTTLS, and returns
// what was sent: the recipients and the data.
func smtpServer(t *testing.T, starttls bool) (addr string, got chan []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan []string, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		tp := textproto.NewConn(c)
		tp.PrintfLine("220 test")
		var rcpts []string
		for {
			line, err := tp.ReadLine()
			if err != nil {
				return
			}
			switch cmd := strings.ToUpper(strings.Fields(line + " x")[0]); cmd {
			case "EHLO":
				if starttls {
					tp.PrintfLine("250-test")
					tp.PrintfLine("250 STARTTLS")
				} else {
					tp.PrintfLine("250 test")
				}
			case "MAIL":
				tp.PrintfLine("250 ok")
			case "RCPT":
				rcpts = append(rcpts, line)
				tp.PrintfLine("250 ok")
			case "DATA":
				tp.PrintfLine("354 go")
				data, _ := tp.ReadDotLines()
				got <- append(rcpts, data...)
				tp.PrintfLine("250 ok")
			case "QUIT":
				tp.PrintfLine("221 bye")
				return
			default:
				tp.PrintfLine("502 no")
			}
		}
	}()
	return l.Addr().String(), got
}

func TestSend(t *testing.T) {
	addr, got := smtpServer(t, false)
	m := &Mailer{Addr: addr, From: "conn3x@example.com"}
	if err := m.Send([]string{"ops@example.com"}, "Conn3x: web\r\nBcc: evil@example.com drifted", "line one\n.dot line"); err != nil {
		t.Fatal(err)
	}
	msg := strings.Join(<-got, "\n")
	for _, want := range []string{"RCPT TO:<ops@example.com>", "Subject: Conn3x: web Bcc: evil@example.com drifted", "line one", ".dot line"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "\nBcc:") {
		t.Errorf("the subject started a header:\n%s", msg)
	}
}

// Off loopback, a server without STARTTLS gets nothing.
func TestSendRefusesCleartext(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		w := bufio.NewWriter(c)
		r := bufio.NewReader(c)
		w.WriteString("220 test\r\n")
		w.Flush()
		r.ReadString('\n')
		w.WriteString("250 test\r\n")
		w.Flush()
		r.ReadString('\n')
	}()
	// Dial the listener, but talk to it as a server that isn't loopback.
	m := &Mailer{Addr: l.Addr().String(), From: "conn3x@example.com"}
	if err := m.sendTo("smtp.example.com", []string{"ops@example.com"}, "s", "b"); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("err = %v", err)
	}
}

func TestParseAddresses(t *testing.T) {
	got, err := ParseAddresses(" ops@example.com, Oncall <oncall@example.com> ,")
	if err != nil || strings.Join(got, ",") != "ops@example.com,oncall@example.com" {
		t.Errorf("%v %v", got, err)
	}
	if _, err := ParseAddresses("ops@example.com, not an address"); err == nil {
		t.Error("a bad address passed")
	}
}
