package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"

	"algoryn.io/relay/internal/config"
)

type watchReloadResult struct {
	files    []string
	debounce time.Duration
	success  bool
}

// configWatchSupervisor watches parent directories rather than file inodes.
// This survives atomic replacements and lets a failed reload recover when a
// missing include (or one of its missing parent directories) is later created.
type configWatchSupervisor struct {
	watcher  *fsnotify.Watcher
	logger   *slog.Logger
	onReload func() watchReloadResult
	updates  chan watchReloadResult
	done     chan struct{}

	validFiles     map[string]struct{}
	candidateFiles map[string]struct{}
	watchedDirs    map[string]struct{}
	debounce       time.Duration
}

func newConfigWatchSupervisor(
	files []string,
	debounce time.Duration,
	logger *slog.Logger,
	onReload func() watchReloadResult,
) (*configWatchSupervisor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}
	s := &configWatchSupervisor{
		watcher:        watcher,
		logger:         logger,
		onReload:       onReload,
		updates:        make(chan watchReloadResult),
		done:           make(chan struct{}),
		validFiles:     fileSet(files),
		candidateFiles: make(map[string]struct{}),
		watchedDirs:    make(map[string]struct{}),
		debounce:       debounce,
	}
	if err := s.syncWatches(); err != nil {
		_ = watcher.Close()
		return nil, err
	}
	return s, nil
}

func (s *configWatchSupervisor) update(ctx context.Context, result watchReloadResult) {
	select {
	case s.updates <- result:
	case <-ctx.Done():
	case <-s.done:
	}
}

func (s *configWatchSupervisor) run(ctx context.Context) {
	defer close(s.done)
	defer s.watcher.Close()

	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	stopTimer := func() {
		if timer != nil && !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timerC = nil
	}
	defer stopTimer()

	schedule := func() {
		delay := s.debounce
		if delay < 0 {
			delay = 0
		}
		if timer == nil {
			timer = time.NewTimer(delay)
		} else {
			stopTimer()
			timer.Reset(delay)
		}
		timerC = timer.C
	}

	for {
		select {
		case <-ctx.Done():
			return
		case result := <-s.updates:
			s.apply(result)
		case <-timerC:
			timerC = nil
			s.apply(s.onReload())
		case event, ok := <-s.watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename|fsnotify.Remove) != 0 &&
				s.relevant(event.Name) {
				schedule()
			}
		case err, ok := <-s.watcher.Errors:
			if !ok {
				return
			}
			s.logger.Warn("file watcher error", "error", err)
		}
	}
}

func (s *configWatchSupervisor) apply(result watchReloadResult) {
	if result.debounce > 0 {
		s.debounce = result.debounce
	}
	if result.success {
		s.validFiles = fileSet(result.files)
		s.candidateFiles = make(map[string]struct{})
	} else {
		s.candidateFiles = fileSet(result.files)
	}
	if err := s.syncWatches(); err != nil {
		s.logger.Warn("file watcher: failed to update watches", "error", err)
	}
}

func (s *configWatchSupervisor) relevant(name string) bool {
	eventPath, err := filepath.Abs(name)
	if err != nil {
		return false
	}
	eventPath = filepath.Clean(eventPath)
	for target := range s.allFiles() {
		if eventPath == target || pathContains(eventPath, target) {
			return true
		}
	}
	return false
}

func (s *configWatchSupervisor) syncWatches() error {
	desired := make(map[string]struct{})
	for file := range s.allFiles() {
		dir, err := nearestExistingDir(filepath.Dir(file))
		if err != nil {
			return fmt.Errorf("find watch directory for %q: %w", file, err)
		}
		desired[dir] = struct{}{}
	}

	for dir := range s.watchedDirs {
		if _, keep := desired[dir]; keep {
			continue
		}
		_ = s.watcher.Remove(dir)
		delete(s.watchedDirs, dir)
	}
	for dir := range desired {
		if _, exists := s.watchedDirs[dir]; exists {
			continue
		}
		if err := s.watcher.Add(dir); err != nil {
			return fmt.Errorf("watch directory %q: %w", dir, err)
		}
		s.watchedDirs[dir] = struct{}{}
	}
	s.logger.Debug("file watcher: watches updated",
		"files", len(s.validFiles)+len(s.candidateFiles),
		"directories", len(s.watchedDirs),
		"debounce", s.debounce,
	)
	return nil
}

func (s *configWatchSupervisor) allFiles() map[string]struct{} {
	files := make(map[string]struct{}, len(s.validFiles)+len(s.candidateFiles))
	for file := range s.validFiles {
		files[file] = struct{}{}
	}
	for file := range s.candidateFiles {
		files[file] = struct{}{}
	}
	return files
}

func fileSet(files []string) map[string]struct{} {
	set := make(map[string]struct{}, len(files))
	for _, file := range files {
		abs, err := filepath.Abs(file)
		if err == nil {
			set[filepath.Clean(abs)] = struct{}{}
		}
	}
	return set
}

// appendTLSWatchFiles makes file-watch reload react to atomic Secret rotations
// and direct certificate/CA updates, not only edits to relay.yaml.
func appendTLSWatchFiles(files []string, cfg *config.Config) []string {
	if cfg == nil {
		return files
	}
	add := func(path string) {
		if path = strings.TrimSpace(path); path != "" {
			files = append(files, path)
		}
	}
	if cfg.Listener.HTTPS.Port > 0 {
		tlsCfg := cfg.Listener.HTTPS.TLS
		add(tlsCfg.CertFile)
		add(tlsCfg.KeyFile)
		add(tlsCfg.ClientCAFile)
		for _, cert := range tlsCfg.Certificates {
			add(cert.CertFile)
			add(cert.KeyFile)
		}
	}
	add(cfg.Observability.Logs.Access.Hash.SecretFile)
	add(cfg.Observability.Logs.OTLP.HeadersFile)
	return files
}

func nearestExistingDir(dir string) (string, error) {
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return "", fmt.Errorf("%q is not a directory", dir)
			}
			return dir, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", err
		}
		dir = parent
	}
}

func pathContains(parent, child string) bool {
	if parent == child {
		return true
	}
	return strings.HasPrefix(child, parent+string(os.PathSeparator))
}
