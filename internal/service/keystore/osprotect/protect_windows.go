// Package osprotect — привязка ключа к учётной записи ОС: Keychain (Mac), DPAPI (Windows).
package osprotect

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows: DPAPI (CryptProtectData) — расшифровать может только эта учётная запись Windows.
var dpapiEntropy = []byte("brassbox/keystore/v1")

// Protector — защита ключа системой. service на Windows не используется
// (DPAPI привязан к учётной записи, отдельной записи нет).
type Protector struct {
	service string
}

// New — защита через DPAPI.
func New(service string) Protector {
	return Protector{service: service}
}

func dataBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func takeBlob(out *windows.DataBlob) []byte {
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) }()
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

// Protect шифрует данные DPAPI.
func (Protector) Protect(plain []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(dataBlob(plain), nil, dataBlob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("dpapi protect: %w", err)
	}
	return takeBlob(&out), nil
}

// Unprotect расшифровывает данные DPAPI.
func (Protector) Unprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(dataBlob(blob), nil, dataBlob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("dpapi unprotect: %w", err)
	}
	return takeBlob(&out), nil
}
