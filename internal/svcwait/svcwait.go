// Package svcwait blocks on service state using service manager
// notifications instead of polling.
package svcwait

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const waitIOCompletion = 0xc0

const anyState = windows.SERVICE_NOTIFY_STOPPED | windows.SERVICE_NOTIFY_START_PENDING |
	windows.SERVICE_NOTIFY_STOP_PENDING | windows.SERVICE_NOTIFY_RUNNING |
	windows.SERVICE_NOTIFY_CONTINUE_PENDING | windows.SERVICE_NOTIFY_PAUSE_PENDING |
	windows.SERVICE_NOTIFY_PAUSED | windows.SERVICE_NOTIFY_DELETE_PENDING

var notifyCallback = windows.NewCallback(func(uintptr) uintptr { return 0 })

// wait registers a one-shot notification on h for mask and sleeps alertably
// until the service manager delivers it. The calling thread must be locked.
func wait(h windows.Handle, mask uint32) error {
	n := &windows.SERVICE_NOTIFY{
		Version:        windows.SERVICE_NOTIFY_STATUS_CHANGE,
		NotifyCallback: notifyCallback,
	}
	if err := windows.NotifyServiceStatusChange(h, mask, n); err != nil {
		return err
	}
	for windows.SleepEx(windows.INFINITE, true) != waitIOCompletion {
	}
	if n.NotificationStatus != 0 {
		return windows.Errno(n.NotificationStatus)
	}
	return nil
}

// Until blocks until the named service's state satisfies done, waiting for
// the service to be created first if needed. done receives the SERVICE_*
// state and the process ID.
func Until(name string, done func(state, pid uint32) bool) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	name16, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	for {
		h, err := windows.OpenService(scm, name16, windows.SERVICE_QUERY_STATUS)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			if err := wait(scm, windows.SERVICE_NOTIFY_CREATED); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		for {
			var st windows.SERVICE_STATUS_PROCESS
			var needed uint32
			err = windows.QueryServiceStatusEx(h, windows.SC_STATUS_PROCESS_INFO,
				(*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &needed)
			if err != nil {
				break
			}
			if done(st.CurrentState, st.ProcessId) {
				windows.CloseServiceHandle(h)
				return nil
			}
			if err = wait(h, anyState); err != nil {
				break
			}
		}
		windows.CloseServiceHandle(h)
		if !errors.Is(err, windows.ERROR_SERVICE_MARKED_FOR_DELETE) {
			return err
		}
	}
}

// RunningOtherThan blocks until the named service runs in a process other
// than old, such as after the service restarts.
func RunningOtherThan(name string, old uint32) (uint32, error) {
	var pid uint32
	err := Until(name, func(state, p uint32) bool {
		pid = p
		return state == windows.SERVICE_RUNNING && p != old
	})
	return pid, err
}

// Exists reports whether the named service is registered.
func Exists(name string) bool {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(scm)
	name16, _ := windows.UTF16PtrFromString(name)
	h, err := windows.OpenService(scm, name16, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false
	}
	windows.CloseServiceHandle(h)
	return true
}
