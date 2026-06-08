package server

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

type sessionStore struct {
	mu       sync.Mutex
	lifetime time.Duration
	items    map[string]time.Time
}

func newSessionStore(hours int) *sessionStore {
	if hours <= 0 {
		hours = 12
	}
	return &sessionStore{
		lifetime: time.Duration(hours) * time.Hour,
		items:    map[string]time.Time{},
	}
}

func (s *sessionStore) create(w http.ResponseWriter, r *http.Request) error {
	token, err := newToken()
	if err != nil {
		return err
	}
	expires := time.Now().Add(s.lifetime)

	s.mu.Lock()
	s.items[token] = expires
	s.cleanupLocked()
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "natcat_session",
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(s.lifetime.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
	return nil
}

func (s *sessionStore) valid(r *http.Request) bool {
	cookie, err := r.Cookie("natcat_session")
	if err != nil || cookie.Value == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	expires, ok := s.items[cookie.Value]
	if !ok || time.Now().After(expires) {
		delete(s.items, cookie.Value)
		return false
	}

	s.items[cookie.Value] = time.Now().Add(s.lifetime)
	return true
}

func (s *sessionStore) clear(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("natcat_session"); err == nil {
		s.mu.Lock()
		delete(s.items, cookie.Value)
		s.mu.Unlock()
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "natcat_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})
}

func (s *sessionStore) cleanupLocked() {
	now := time.Now()
	for token, expires := range s.items {
		if now.After(expires) {
			delete(s.items, token)
		}
	}
}

func newToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
