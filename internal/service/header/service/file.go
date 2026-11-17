package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"brassbox/internal/errs"
	localConstant "brassbox/internal/service/header/service/constant"
	localModel "brassbox/internal/service/header/service/model"
)

// slot — где лежит копия заголовка.
type slot struct {
	off  int64
	size int
}

var slots = [2]slot{
	{off: localConstant.SlotAOff, size: localConstant.SlotASize},
	{off: localConstant.SlotBOff, size: localConstant.SlotBSize},
}

// state — живая копия заголовка и её место.
type state struct {
	h    localModel.Header
	slot int // 0 = A, 1 = B
}

// readState читает первые 4 КиБ и выбирает живую копию (целую, с большим Seq).
func readState(f *os.File) (state, error) {
	buf := make([]byte, localConstant.Size)
	if _, err := f.ReadAt(buf, 0); err != nil {
		if errors.Is(err, io.EOF) {
			return state{}, fmt.Errorf("%w: file shorter than header", errs.VaultInvalid)
		}
		return state{}, fmt.Errorf("read header: %w", err)
	}
	if !bytes.HasPrefix(buf, []byte(localConstant.Magic)) {
		return state{}, fmt.Errorf("%w: no magic", errs.VaultInvalid)
	}

	best, found := state{}, false
	for i, s := range slots {
		h, ok := decodeSlot(buf[s.off : s.off+int64(s.size)])
		if ok && (!found || h.Seq > best.h.Seq) {
			best, found = state{h: h, slot: i}, true
		}
	}
	if !found {
		return state{}, fmt.Errorf("%w: both header copies are damaged", errs.VaultDamaged)
	}
	return best, nil
}

// writeNext пишет h (Seq+1) в другую копию — живая остаётся нетронутой до fsync.
func writeNext(f *os.File, st *state) error {
	next := st.h
	next.Seq++
	target := 1 - st.slot

	b, err := encodeSlot(next, slots[target].size)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(b, slots[target].off); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync header: %w", err)
	}
	st.h, st.slot = next, target
	return nil
}

// encodeSlot: длина | JSON | SHA-256(длина|JSON) | нули до size.
func encodeSlot(h localModel.Header, size int) ([]byte, error) {
	js, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	if localConstant.LenSize+len(js)+localConstant.HashSize > size {
		return nil, fmt.Errorf("header json too big: %d bytes", len(js))
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint32(out, uint32(len(js))) //nolint:gosec // G115: len(js) < slot size (checked above)
	copy(out[localConstant.LenSize:], js)
	end := localConstant.LenSize + len(js)
	sum := sha256.Sum256(out[:end])
	copy(out[end:], sum[:])
	return out, nil
}

// decodeSlot — копия целая (хэш сошёлся) и осмысленная.
func decodeSlot(b []byte) (localModel.Header, bool) {
	var h localModel.Header
	if len(b) < localConstant.LenSize+localConstant.HashSize {
		return h, false
	}
	n := int(binary.BigEndian.Uint32(b))
	end := localConstant.LenSize + n
	if n == 0 || end+localConstant.HashSize > len(b) {
		return h, false
	}
	sum := sha256.Sum256(b[:end])
	if !bytes.Equal(sum[:], b[end:end+localConstant.HashSize]) {
		return h, false
	}
	if err := json.Unmarshal(b[localConstant.LenSize:end], &h); err != nil {
		return h, false
	}
	if h.Format != localConstant.Format ||
		len(h.VaultID) != localConstant.VaultIDSize ||
		len(h.DEKCheck) != localConstant.CheckSize ||
		h.Master == nil || len(h.Master.Sealed) == 0 ||
		(h.Password != nil && (len(h.Password.Salt) == 0 || len(h.Password.Sealed) == 0)) {
		return h, false
	}
	return h, true
}
