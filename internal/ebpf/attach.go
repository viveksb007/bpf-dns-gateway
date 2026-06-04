package ebpf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Attachment owns the TCX links holding the ingress and egress programs
// on a single interface. Calling Close detaches both programs (TCX
// auto-detach also fires when the process exits and the link fds drop).
type Attachment struct {
	Ifindex int
	Ingress link.Link
	Egress  link.Link
}

// Close detaches both programs by closing their link fds. Errors from
// either close are joined and returned together.
func (a *Attachment) Close() error {
	var errs []error
	if a.Ingress != nil {
		if err := a.Ingress.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close ingress: %w", err))
		}
		a.Ingress = nil
	}
	if a.Egress != nil {
		if err := a.Egress.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close egress: %w", err))
		}
		a.Egress = nil
	}
	return errors.Join(errs...)
}

// AttachManager tracks per-interface TCX attachments. It is safe for
// concurrent use by the netlink monitor goroutine and the controller's
// shutdown goroutine.
type AttachManager struct {
	mu          sync.Mutex
	attachments map[int]*Attachment
	loader      *Loader
}

// NewAttachManager wraps a loaded Loader so its programs can be attached
// to interfaces via TCX.
func NewAttachManager(l *Loader) *AttachManager {
	return &AttachManager{
		loader:      l,
		attachments: make(map[int]*Attachment),
	}
}

// Attach attaches both ingress and egress programs to the given ifindex
// using TCX (kernel 6.6+). If an attachment already exists for ifindex,
// returns nil (idempotent).
func (m *AttachManager) Attach(ifindex int) error {
	if ifindex <= 0 {
		return fmt.Errorf("invalid ifindex %d", ifindex)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.attachments[ifindex]; ok {
		return nil
	}

	ingressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   m.loader.IngressProgram(),
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach TCX ingress on ifindex %d: %w", ifindex, err)
	}

	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   m.loader.EgressProgram(),
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = ingressLink.Close()
		return fmt.Errorf("attach TCX egress on ifindex %d: %w", ifindex, err)
	}

	m.attachments[ifindex] = &Attachment{
		Ifindex: ifindex,
		Ingress: ingressLink,
		Egress:  egressLink,
	}
	return nil
}

// Detach detaches both programs from the given ifindex. Returns nil if
// no attachment exists (idempotent).
func (m *AttachManager) Detach(ifindex int) error {
	m.mu.Lock()
	a, ok := m.attachments[ifindex]
	if !ok {
		m.mu.Unlock()
		return nil
	}
	delete(m.attachments, ifindex)
	m.mu.Unlock()
	return a.Close()
}

// DetachAll detaches every tracked interface. Errors are joined.
func (m *AttachManager) DetachAll() error {
	m.mu.Lock()
	all := m.attachments
	m.attachments = make(map[int]*Attachment)
	m.mu.Unlock()

	var errs []error
	for ifindex, a := range all {
		if err := a.Close(); err != nil {
			errs = append(errs, fmt.Errorf("ifindex %d: %w", ifindex, err))
		}
	}
	return errors.Join(errs...)
}

// AttachedCount returns the number of interfaces currently attached.
func (m *AttachManager) AttachedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.attachments)
}

// IsAttached reports whether ifindex has an active attachment.
func (m *AttachManager) IsAttached(ifindex int) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.attachments[ifindex]
	return ok
}
