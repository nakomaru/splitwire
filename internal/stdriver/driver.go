package stdriver

import (
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

// ServiceName is the kernel driver service name used by the Mullvad app as well.
const ServiceName = "mullvad-split-tunnel"

const devicePath = `\\.\MULLVADSPLITTUNNEL`

const (
	methodBuffered = 0
	methodNeither  = 3
)

func ctlCode(function, method uint32) uint32 {
	const deviceType = 0x8000
	const fileAnyAccess = 0
	return deviceType<<16 | fileAnyAccess<<14 | function<<2 | method
}

var (
	ioctlInitialize        = ctlCode(1, methodBuffered)
	ioctlDequeueEvent      = ctlCode(2, methodBuffered)
	ioctlRegisterProcesses = ctlCode(3, methodBuffered)
	ioctlRegisterIPs       = ctlCode(4, methodBuffered)
	ioctlGetIPs            = ctlCode(5, methodBuffered)
	ioctlSetConfiguration  = ctlCode(6, methodBuffered)
	ioctlClearConfig       = ctlCode(8, methodNeither)
	ioctlGetState          = ctlCode(9, methodBuffered)
	ioctlReset             = ctlCode(11, methodNeither)
)

// State is the driver's ST_DRIVER_STATE.
type State uint64

const (
	StateNone        State = 0
	StateStarted     State = 1
	StateInitialized State = 2
	StateReady       State = 3
	StateEngaged     State = 4
	StateZombie      State = 5
)

func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateStarted:
		return "started"
	case StateInitialized:
		return "initialized"
	case StateReady:
		return "ready"
	case StateEngaged:
		return "engaged"
	case StateZombie:
		return "zombie"
	}
	return fmt.Sprintf("unknown(%d)", uint64(s))
}

// ErrInUse means another process, such as the Mullvad daemon or a second
// splitwire instance, holds the driver's exclusive device handle.
var ErrInUse = errors.New("split tunnel driver is in use by another process")

// ErrNotLoaded means the driver service is not running.
var ErrNotLoaded = errors.New("split tunnel driver is not loaded")

// Driver is an open handle to the split tunnel device. The device admits one
// handle at a time.
type Driver struct {
	h windows.Handle
}

// Open opens the device.
func Open() (*Driver, error) {
	name, err := windows.UTF16PtrFromString(devicePath)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND):
		return nil, ErrNotLoaded
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return nil, fmt.Errorf("%w (%v)", ErrInUse, err)
	case err != nil:
		return nil, fmt.Errorf("open %s: %w", devicePath, err)
	}
	return &Driver{h: h}, nil
}

// Describe opens the device for a moment and reports its state, or why it
// could not open it. Opening needs administrator rights.
func Describe() string {
	d, err := Open()
	switch {
	case errors.Is(err, ErrNotLoaded):
		return "not loaded"
	case errors.Is(err, ErrInUse):
		return "in use by a running tunnel"
	case err != nil:
		return err.Error()
	}
	defer d.Close()
	st, err := d.State()
	if err != nil {
		return err.Error()
	}
	return "loaded, " + st.String()
}

// CancelPending cancels outstanding requests, such as a blocked DequeueEvent.
func (d *Driver) CancelPending() {
	if d.h != 0 {
		windows.CancelIoEx(d.h, nil)
	}
}

// Close closes the handle once no request is outstanding. The driver keeps
// its state after the handle closes, so callers disengage it with Reset first.
func (d *Driver) Close() error {
	if d.h == 0 {
		return nil
	}
	err := windows.CloseHandle(d.h)
	d.h = 0
	return err
}

func (d *Driver) ioctl(code uint32, in []byte, outSize int) ([]byte, error) {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(ev)

	var inPtr, outPtr *byte
	if len(in) > 0 {
		inPtr = &in[0]
	}
	out := make([]byte, outSize)
	if outSize > 0 {
		outPtr = &out[0]
	}
	ov := windows.Overlapped{HEvent: ev}
	var n uint32
	err = windows.DeviceIoControl(d.h, code, inPtr, uint32(len(in)), outPtr, uint32(len(out)), &n, &ov)
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(d.h, &ov, &n, true)
	}
	if err != nil {
		return nil, err
	}
	return out[:n], nil
}

// State queries the driver state.
func (d *Driver) State() (State, error) {
	out, err := d.ioctl(ioctlGetState, nil, 8)
	if err != nil {
		return 0, fmt.Errorf("get driver state: %w", err)
	}
	if len(out) < 8 {
		return 0, fmt.Errorf("get driver state: short reply (%d bytes)", len(out))
	}
	return State(binary.LittleEndian.Uint64(out)), nil
}

// Reset tears down all driver subsystems, returning it to StateStarted.
func (d *Driver) Reset() error {
	if _, err := d.ioctl(ioctlReset, nil, 0); err != nil {
		return fmt.Errorf("reset driver: %w", err)
	}
	return nil
}

// Initialize starts the driver subsystems. Its WFP filters go into the given
// sublayers, which must already exist.
func (d *Driver) Initialize(baselineSublayer, dnsSublayer windows.GUID) error {
	if _, err := d.ioctl(ioctlInitialize, encodeSublayerGUIDs(baselineSublayer, dnsSublayer), 0); err != nil {
		return fmt.Errorf("initialize driver: %w", err)
	}
	return nil
}

// RegisterProcesses hands the driver a snapshot of running processes. The
// driver tracks processes on its own afterward.
func (d *Driver) RegisterProcesses(procs []Process) error {
	buf, err := encodeProcesses(procs)
	if err != nil {
		return err
	}
	if _, err := d.ioctl(ioctlRegisterProcesses, buf, 0); err != nil {
		return fmt.Errorf("register processes: %w", err)
	}
	return nil
}

// RegisterAddresses sets the redirect addresses. It may be called again
// whenever an address changes.
func (d *Driver) RegisterAddresses(a Addresses) error {
	buf, err := encodeAddresses(a)
	if err != nil {
		return err
	}
	if _, err := d.ioctl(ioctlRegisterIPs, buf, 0); err != nil {
		return fmt.Errorf("register addresses: %w", err)
	}
	return nil
}

// Addresses reads back the registered addresses.
func (d *Driver) Addresses() (Addresses, error) {
	out, err := d.ioctl(ioctlGetIPs, nil, ipAddressesSize)
	if err != nil {
		return Addresses{}, fmt.Errorf("get addresses: %w", err)
	}
	return decodeAddresses(out)
}

// SetConfiguration replaces the set of split images, given as NT device paths.
func (d *Driver) SetConfiguration(devicePaths []string) error {
	if len(devicePaths) == 0 {
		return d.ClearConfiguration()
	}
	buf, err := encodeConfiguration(devicePaths)
	if err != nil {
		return err
	}
	if _, err := d.ioctl(ioctlSetConfiguration, buf, 0); err != nil {
		return fmt.Errorf("set configuration: %w", err)
	}
	return nil
}

// ClearConfiguration removes all split images.
func (d *Driver) ClearConfiguration() error {
	if _, err := d.ioctl(ioctlClearConfig, nil, 0); err != nil {
		return fmt.Errorf("clear configuration: %w", err)
	}
	return nil
}

// DequeueEvent blocks until the driver reports an event or CancelPending
// cancels the request.
func (d *Driver) DequeueEvent() (Event, error) {
	out, err := d.ioctl(ioctlDequeueEvent, nil, 8192)
	if err != nil {
		return Event{}, err
	}
	return decodeEvent(out)
}
