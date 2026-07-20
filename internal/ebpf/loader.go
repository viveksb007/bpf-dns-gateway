package ebpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// DefaultPinDir is the bpffs path under which shared maps are pinned.
const DefaultPinDir = "/sys/fs/bpf/dns-gateway"

// Loader owns the loaded eBPF objects and their pinned map directory.
//
// On construction, the maps are loaded with a pin path so they survive
// independently of the program lifecycle if needed. The programs themselves
// are not attached here — callers attach via TCX in the controller.
type Loader struct {
	objs   DnsGatewayObjects
	pinDir string

	// configMu serializes writers of config_map[0]. SetBypass is a
	// read-modify-write, and the health checker and the shutdown path
	// may call it concurrently; without the lock one write can be lost.
	configMu sync.Mutex
}

// New loads the embedded eBPF object file, removes the MEMLOCK rlimit,
// and pins the maps under pinDir. pinDir must reside on a bpffs mount
// (typically /sys/fs/bpf). The directory is created with 0755 permissions
// if it does not already exist.
func New(pinDir string) (*Loader, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	if pinDir == "" {
		pinDir = DefaultPinDir
	}
	if err := os.MkdirAll(pinDir, 0o755); err != nil {
		return nil, fmt.Errorf("create pin dir %s: %w", pinDir, err)
	}

	spec, err := LoadDnsGateway()
	if err != nil {
		return nil, fmt.Errorf("load dns_gateway spec: %w", err)
	}

	// Mark every map for pin-by-name and provide the directory so
	// LoadAndAssign creates pinned files automatically. Without this,
	// PinPath alone is ignored — cilium/ebpf only honors PinPath for
	// maps whose spec opts in via PinByName.
	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinByName
	}

	l := &Loader{pinDir: pinDir}
	opts := ebpf.CollectionOptions{
		Maps:     ebpf.MapOptions{PinPath: pinDir},
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats},
	}
	if err := spec.LoadAndAssign(&l.objs, &opts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, fmt.Errorf("verifier rejected programs: %+v", verr)
		}
		return nil, fmt.Errorf("load and assign objects: %w", err)
	}
	return l, nil
}

// Close releases program and map file descriptors. Pinned maps remain on
// the bpffs until Unpin is called.
func (l *Loader) Close() error {
	return l.objs.Close()
}

// Unpin removes every pinned map file under the loader's pin directory and
// then removes the directory itself. Should only be called after programs
// have been detached and the loader closed (or about to be).
func (l *Loader) Unpin() error {
	entries, err := os.ReadDir(l.pinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read pin dir %s: %w", l.pinDir, err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(l.pinDir, e.Name())); err != nil {
			return fmt.Errorf("remove pinned map %s: %w", e.Name(), err)
		}
	}
	if err := os.Remove(l.pinDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove pin dir %s: %w", l.pinDir, err)
	}
	return nil
}

// IngressProgram returns the loaded ingress program (for TC attach).
func (l *Loader) IngressProgram() *ebpf.Program {
	return l.objs.DnsGatewayIngress
}

// EgressProgram returns the loaded egress program (for TC attach).
func (l *Loader) EgressProgram() *ebpf.Program {
	return l.objs.DnsGatewayEgress
}

// PinDir returns the directory under which maps are pinned.
func (l *Loader) PinDir() string {
	return l.pinDir
}
