package manager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"splitwire/internal/bootstrap"
	"splitwire/internal/ipc"
)

// usersFile lists the SIDs of the users who may control the manager, one
// per line, in the configs folder that only SYSTEM and Administrators can
// read.
const usersFile = "users"

func usersPath() (string, error) {
	dir, err := bootstrap.ConfigsDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, usersFile), nil
}

// Users lists the SIDs of the users who may control the manager.
func Users() []string {
	path, err := usersPath()
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var sids []string
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			sids = append(sids, l)
		}
	}
	return sids
}

func writeUsers(sids []string) error {
	path, err := usersPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(sids, "\n")+"\n"), 0o600)
}

// addUser adds sid to the users unless it is there already.
func addUser(sid string) error {
	if _, err := windows.StringToSid(sid); err != nil {
		return fmt.Errorf("%q is not a user SID", sid)
	}
	sids := Users()
	for _, s := range sids {
		if strings.EqualFold(s, sid) {
			return nil
		}
	}
	log.Printf("Allowing %s to control SplitWire", accountName(sid))
	return writeUsers(append(sids, sid))
}

// accountName is DOMAIN\user for a SID, or the SID itself.
func accountName(sid string) string {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return sid
	}
	account, domain, _, err := s.LookupAccount("")
	if err != nil {
		return sid
	}
	return domain + `\` + account
}

// CurrentUser is the SID of the user this process runs as.
func CurrentUser() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

// Leave removes sid from the users and has the running manager reopen its
// pipe without that user. The last user uninstalls splitwire instead.
func Leave(sid string) error {
	sids := Users()
	var kept []string
	for _, s := range sids {
		if !strings.EqualFold(s, sid) {
			kept = append(kept, s)
		}
	}
	if len(kept) == len(sids) {
		return fmt.Errorf("%s is not a SplitWire user", accountName(sid))
	}
	if len(kept) == 0 {
		return errors.New("this is the last SplitWire user; uninstall SplitWire instead")
	}
	if err := writeUsers(kept); err != nil {
		return err
	}
	log.Printf("Removed %s from SplitWire's users", accountName(sid))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := ipc.Call(ctx, ipc.Request{Op: ipc.OpUsers}); err != nil {
		log.Printf("Warning: the manager did not reload its users (%v); they apply when it next starts", err)
	}
	return nil
}
