package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"natcat/internal/core"
)

type Server struct {
	store   *core.Store
	manager *core.Manager
	static  fs.FS
	session *sessionStore
}

func New(store *core.Store, manager *core.Manager, static fs.FS) *Server {
	return &Server{
		store:   store,
		manager: manager,
		static:  static,
		session: newSessionStore(store.SessionHours()),
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.login)
	mux.HandleFunc("/api/logout", s.requireAuth(s.logout))
	mux.HandleFunc("/api/me", s.requireAuth(s.me))
	mux.HandleFunc("/api/events", s.requireAuth(s.events))
	mux.HandleFunc("/api/server-groups", s.requireAuth(s.serverGroups))
	mux.HandleFunc("/api/instances", s.requireAuth(s.instances))
	mux.HandleFunc("/api/instances/", s.requireAuth(s.instanceByID))
	mux.Handle("/", s.staticHandler())
	return secureHeaders(mux)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}

	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}

	if !core.CheckPassword(s.store.Admin(), body.Username, body.Password) {
		writeError(w, http.StatusUnauthorized, "用户名或密码错误")
		return
	}
	if err := s.session.create(w, r); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": body.Username})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.session.clear(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": s.store.Admin().Username})
}

func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "event stream is not supported")
		return
	}

	events, unsubscribe := s.manager.SubscribeRuntime()
	defer unsubscribe()

	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	if !writeSSE(w, flusher, "ready", map[string]bool{"ok": true}) {
		return
	}

	heartbeat := time.NewTicker(20 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok || !writeSSE(w, flusher, "runtime", event) {
				return
			}
		case <-heartbeat.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *Server) serverGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.store.ServerGroups())
	case http.MethodPut:
		var groups core.ServerGroupsConfig
		if !decodeJSON(w, r, &groups) {
			return
		}
		saved, err := s.store.UpdateServerGroups(groups)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		go s.applyServerGroupsToRunningInstances()
		writeJSON(w, http.StatusOK, saved)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) applyServerGroupsToRunningInstances() {
	for _, cfg := range s.store.ListInstances() {
		if !cfg.Enabled || (cfg.STUNMode != "group" && cfg.KeepAliveMode != "group") || !s.manager.IsRunning(cfg.ID) {
			continue
		}
		_ = s.manager.ReplaceConfig(cfg, cfg, true)
	}
}

func (s *Server) instances(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.manager.List())
	case http.MethodPost:
		var cfg core.InstanceConfig
		if !decodeJSON(w, r, &cfg) {
			return
		}
		created, err := s.store.AddInstance(cfg)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.manager.ApplyConfig(created)
		snapshot, _ := s.manager.Snapshot(created.ID)
		writeJSON(w, http.StatusCreated, snapshot)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) instanceByID(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/instances/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	id := parts[0]

	if len(parts) == 2 {
		switch parts[1] {
		case "start":
			s.startInstance(w, r, id)
			return
		case "stop":
			s.stopInstance(w, r, id)
			return
		case "check":
			s.checkInstance(w, r, id)
			return
		case "notify-test":
			s.testNotifyScript(w, r, id)
			return
		}
	}
	if len(parts) > 1 {
		http.NotFound(w, r)
		return
	}

	switch r.Method {
	case http.MethodGet:
		snapshot, ok := s.manager.Snapshot(id)
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, snapshot)
	case http.MethodPut:
		wasRunning := s.manager.IsRunning(id)
		oldCfg, ok := s.store.GetInstance(id)
		if !ok {
			writeError(w, http.StatusNotFound, "instance not found")
			return
		}
		var cfg core.InstanceConfig
		if !decodeJSON(w, r, &cfg) {
			return
		}
		updated, err := s.store.UpdateInstance(id, cfg)
		if err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(w, status, err.Error())
			return
		}
		if err := s.manager.ReplaceConfig(oldCfg, updated, wasRunning); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		snapshot, _ := s.manager.Snapshot(updated.ID)
		writeJSON(w, http.StatusOK, snapshot)
	case http.MethodDelete:
		_ = s.manager.Stop(id)
		if err := s.store.DeleteInstance(id); err != nil {
			status := http.StatusBadRequest
			if errors.Is(err, os.ErrNotExist) {
				status = http.StatusNotFound
			}
			writeError(w, status, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) startInstance(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := s.manager.Start(id); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	snapshot, _ := s.manager.Snapshot(id)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) stopInstance(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if err := s.manager.Stop(id); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	snapshot, _ := s.manager.Snapshot(id)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) checkInstance(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	check, err := s.manager.CheckTCPPort(r.Context(), id)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, check)
}

func (s *Server) testNotifyScript(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var body struct {
		Script string               `json:"script"`
		Config *core.InstanceConfig `json:"config"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	snapshot, ok := s.manager.Snapshot(id)
	if !ok {
		writeError(w, http.StatusNotFound, "instance not found")
		return
	}
	cfg := snapshot.Config
	if body.Config != nil {
		cfg = *body.Config
		if cfg.ID == "" {
			cfg.ID = snapshot.Config.ID
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	result, err := core.RunNotifyScriptTest(ctx, cfg, snapshot.Runtime, body.Script)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, http.StatusBadRequest, "通知脚本测试超时")
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.session.valid(r) {
			writeError(w, http.StatusUnauthorized, "需要登录")
			return
		}
		next(w, r)
	}
}

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServer(http.FS(s.static))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(s.static, path); err != nil {
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, value any) bool {
	raw, err := json.Marshal(value)
	if err != nil {
		return false
	}
	if _, err := w.Write([]byte("event: " + event + "\n")); err != nil {
		return false
	}
	if _, err := w.Write([]byte("data: ")); err != nil {
		return false
	}
	if _, err := w.Write(raw); err != nil {
		return false
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return false
	}
	flusher.Flush()
	return true
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, "method not allowed")
}
