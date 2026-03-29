package config

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

func Watch(path string, onChange func(*Config)) error {
	_, _ = path, onChange
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// TODO: implement fsnotify-based config reload and invoke onChange with parsed config.
	return nil
}

func handleSIGHUP(onChange func(*Config)) {
	_ = onChange
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	// TODO: implement SIGHUP-triggered config reload callback.
}
