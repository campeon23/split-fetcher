//go:build windows
// +build windows

package pprofutils

import (
	"os"
	"os/signal"
	"syscall"
)

func (p *PprofUtils) handleOSSignals() <-chan bool {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT)
    
	done := make(chan bool, 1)
	go func() {
		<-signalChan
		done <- true
	}()
    
	return done
}
