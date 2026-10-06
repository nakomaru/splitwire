package tray

import (
	"context"
	"fmt"
	"time"

	"fyne.io/systray"

	"splitwire/internal/update"
)

// updateInterval is how often the app looks for a newer release.
const updateInterval = 24 * time.Hour

// watchUpdates looks for a newer release now and every updateInterval,
// offering one in the menu.
func (a *app) watchUpdates() {
	tk := time.NewTicker(updateInterval)
	defer tk.Stop()
	for {
		a.checkUpdate()
		<-tk.C
	}
}

// checkUpdate fetches the newest release's signed manifest and records it
// when it is newer than this copy. It returns nil when this copy is the
// newest.
func (a *app) checkUpdate() (*update.Manifest, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	m, err := update.Latest(ctx)
	if err != nil {
		return nil, err
	}
	if !update.Newer(m.Version, Version) {
		m = nil
	}
	a.mu.Lock()
	a.latest = m
	a.refreshLocked()
	a.mu.Unlock()
	return m, nil
}

// updateApp is the menu's update item: it checks for a newer release when
// none is known, then offers to install it and restarts into it.
func (a *app) updateApp() {
	a.mu.Lock()
	m := a.latest
	a.mu.Unlock()
	if m == nil {
		var err error
		if m, err = a.checkUpdate(); err != nil {
			errorBox("Could not check for updates:\n\n%v", err)
			return
		}
		if m == nil {
			infoBox("SplitWire %s is the newest version.", Version)
			return
		}
	}
	intro := fmt.Sprintf("Updates SplitWire from version %s to %s.", Version, m.Version)
	a.mu.Lock()
	running, boot := len(a.status.Tunnels) > 0, a.status.Boot
	a.mu.Unlock()
	switch {
	case running && boot:
		intro += " Running tunnels reconnect."
	case running:
		intro += " Running tunnels disconnect."
	}
	if _, ok := askOptions("Update SplitWire", intro, nil, "Update"); !ok {
		return
	}
	sid, err := ownSID()
	if err != nil {
		errorBox("%v", err)
		return
	}
	if !runElevated(selfExe(), "update", "--user="+sid) {
		return
	}
	installed, err := installedExe()
	if err != nil {
		errorBox("%v", err)
		return
	}
	a.next = installed
	systray.Quit()
}

// updateTitle is the update item's text.
func updateTitle(m *update.Manifest) string {
	if m == nil {
		return "Check for updates..."
	}
	return "Update to SplitWire " + m.Version + " (administrator)..."
}
