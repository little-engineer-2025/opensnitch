package common

import (
	"sync"
	"time"

	"github.com/evilsocket/opensnitch/daemon/log"
)

// default arguments for various functions
var (
	EnableRule     = true
	DoLogErrors    = true
	ForcedDelRules = true
	ReloadRules    = true
	RestoreChains  = true
	BackupChains   = true
	ReloadConf     = true

	DefaultCheckInterval = 10 * time.Second
	RulesCheckerDisabled = "0s"
)

type (
	callback     func()
	callbackBool func() bool

	// Common holds common fields and functionality of both firewalls,
	// iptables and nftables.
	Common struct {
		RulesChecker       *time.Ticker
		ErrChan            chan string
		stopChecker        chan struct{}
		RulesCheckInterval time.Duration
		QueueNum           uint16
		Running            bool
		Intercepting       bool
		FwEnabled          bool
		sync.RWMutex
	}
)

// ErrorsChan returns the channel where the errors are sent to.
func (c *Common) ErrorsChan() <-chan string {
	if c == nil {
		return c.ErrChan
	}
	return nil
}

// ErrChanEmpty checks if the errors channel is empty.
func (c *Common) ErrChanEmpty() bool {
	if c == nil {
		return len(c.ErrChan) == 0
	}
	return false
}

// SendError sends an error to the channel of errors.
func (c *Common) SendError(err string) {
	if c == nil {
		log.Error("SendError: c is nil")
		return
	}
	log.Warning("%s", err)

	if len(c.ErrChan) >= cap(c.ErrChan) {
		log.Debug("fw errors channel full, emptying errChan")
		for e := range c.ErrChan {
			log.Warning("%s", e)
			if c.ErrChanEmpty() {
				break
			}
		}
		return
	}
	select {
	case c.ErrChan <- err:
	case <-time.After(100 * time.Millisecond):
		log.Warning("SendError() channel locked? REVIEW")
	}
}

func (c *Common) SetRulesCheckerInterval(interval string) {
	if c == nil {
		log.Error("SetRulesCheckerInterval: c is nil")
		return
	}
	dur, err := time.ParseDuration(interval)
	if err != nil {
		log.Warning("Invalid rules checker interval (falling back to %s): %s", DefaultCheckInterval, err)
		c.RulesCheckInterval = DefaultCheckInterval
		return
	}

	c.RulesCheckInterval = dur
}

// SetQueueNum sets the queue number used by the firewall.
// It's the queue where all intercepted connections will be sent.
func (c *Common) SetQueueNum(qNum uint16) {
	if c == nil {
		log.Error("SetQueueNum: c is nil")
		return
	}
	c.Lock()
	defer c.Unlock()
	c.QueueNum = qNum
}

// IsRunning returns if the firewall is running or not.
func (c *Common) IsRunning() bool {
	if c != nil {
		c.RLock()
		defer c.RUnlock()

		return c.Running
	}
	return false
}

// IsFirewallEnabled returns if the firewall is running or not.
func (c *Common) IsFirewallEnabled() bool {
	if c != nil {
		c.RLock()
		defer c.RUnlock()

		return c.FwEnabled
	}
	return false
}

// IsIntercepting returns if the firewall is running or not.
func (c *Common) IsIntercepting() bool {
	if c != nil {
		c.RLock()
		defer c.RUnlock()

		return c.Intercepting
	}
	return false
}

// NewRulesChecker starts monitoring interception rules.
// We expect to have 2 rules loaded: one to intercept DNS responses and another one
// to intercept network traffic.
func (c *Common) NewRulesChecker(areRulesLoaded callbackBool, reloadRules callback) {
	if c == nil {
		log.Error("NewRulesChecker: c is nil")
		return
	}
	c.Lock()
	defer c.Unlock()
	if c.RulesCheckInterval.String() == RulesCheckerDisabled {
		log.Info("Fw rules checker disabled ...")
		return
	}

	if c.RulesChecker != nil {
		c.RulesChecker.Stop()
		select {
		case c.stopChecker <- struct{}{}:
		case <-time.After(5 * time.Millisecond):
			log.Error("NewRulesChecker: timed out stopping monitor rules")
		}
	}
	c.stopChecker = make(chan struct{}, 1)
	log.Info("Starting new fw checker every %s ...", c.RulesCheckInterval)
	c.RulesChecker = time.NewTicker(c.RulesCheckInterval)

	go startCheckingRules(c.stopChecker, c.RulesChecker, areRulesLoaded, reloadRules)
}

// StartCheckingRules monitors if our rules are loaded.
// If the rules to intercept traffic are not loaded, we'll try to insert them again.
func startCheckingRules(exitChan <-chan struct{}, rulesChecker *time.Ticker, areRulesLoaded callbackBool, reloadRules callback) {
	for {
		select {
		case <-exitChan:
			goto Exit
		case _, active := <-rulesChecker.C:
			if !active {
				goto Exit
			}

			if areRulesLoaded() == false {
				reloadRules()
			}
		}
	}

Exit:
	log.Info("exit checking firewall rules")
}

// StopCheckingRules stops checking if firewall rules are loaded.
func (c *Common) StopCheckingRules() {
	c.Lock()
	defer c.Unlock()

	if c.RulesChecker != nil {
		select {
		case c.stopChecker <- struct{}{}:
			close(c.stopChecker)
		case <-time.After(5 * time.Millisecond):
			// We should not arrive here
			log.Error("StopCheckingRules: timed out stopping monitor rules")
		}

		c.RulesChecker.Stop()
		c.RulesChecker = nil
	}
}

// FIXME Not used
func (c *Common) reloadCallback(callback func()) {
	if c == nil {
		log.Error("reloadCallback: c is nil")
		return
	}
	callback()
}
