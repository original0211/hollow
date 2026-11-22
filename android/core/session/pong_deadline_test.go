package session

// NP-1118-66 grids for audit NP-1118-63 S2 (Go side): a carrier
// whose peer completes the upgrade but then goes totally silent
// must be declared dead at the pong-silence bound through the
// ordinary shutdown path; a carrier receiving any inbound traffic
// stays alive.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"hollow/androidcore/core"
)

func silentOrChattyServer(t *testing.T, chatty bool) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		// Swallow pings without ponging: silence must be total
		// unless the chatty variant sends data frames.
		c.SetPingHandler(func(string) error { return nil })
		if chatty {
			go func() {
				tk := time.NewTicker(100 * time.Millisecond)
				defer tk.Stop()
				for range tk.C {
					if err := c.WriteMessage(websocket.TextMessage, []byte("x")); err != nil {
						return
					}
				}
			}()
		}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func dialAttached(t *testing.T, srv *httptest.Server) *wsTransport {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	direct := (&net.Dialer{}).DialContext
	tr, err := dialCarrier(context.Background(), url, direct, nil, "")
	if err != nil {
		t.Fatalf("dialCarrier: %v", err)
	}
	psk := make([]byte, 32)
	client := core.NewClient(tr, core.ClientOptions{PSK: psk, KeyID: 1})
	tr.attach(client)
	return tr
}

func TestPongSilenceDeclaresCarrierDead(t *testing.T) {
	old := pongSilenceBound
	pongSilenceBound = 400 * time.Millisecond
	defer func() { pongSilenceBound = old }()

	tr := dialAttached(t, silentOrChattyServer(t, false))
	select {
	case <-tr.done:
		// shutdown ran: the carrier was declared dead at the bound
	case <-time.After(3 * time.Second):
		t.Fatal("silent carrier was not declared dead within 3s (bound 400ms)")
	}
}

func TestInboundTrafficKeepsCarrierAlive(t *testing.T) {
	old := pongSilenceBound
	pongSilenceBound = 400 * time.Millisecond
	defer func() { pongSilenceBound = old }()

	tr := dialAttached(t, silentOrChattyServer(t, true))
	select {
	case <-tr.done:
		t.Fatal("chatty carrier was declared dead despite inbound traffic")
	case <-time.After(1500 * time.Millisecond):
		// still alive after ~4x the bound
	}
	tr.shutdown()
}
