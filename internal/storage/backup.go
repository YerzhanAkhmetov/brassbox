package storage

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"

	"brassbox/internal/errs"
	"brassbox/internal/service/crypto"
)

// VacuumInto — зашифрованная копия базы в новый файл dst (тем же DEK, тем же VFS:
// первые 4 КиБ копии пустые — заголовок дописывает вызывающий, header.Clone).
// Ключ копии передаётся только в URI параметра запроса, не в тексте SQL.
func VacuumInto(ctx context.Context, db *sql.DB, dst string, dek []byte) error {
	if len(dek) != crypto.KeySize {
		return fmt.Errorf("%w: key length %d", errs.InvalidRequest, len(dek))
	}
	if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", errs.VaultExists, dst)
	}
	uri := fileURI(dst, url.Values{"vfs": {VFSName}, "hexkey": {hex.EncodeToString(dek)}})
	if _, err := db.ExecContext(ctx, "VACUUM INTO ?", uri); err != nil {
		return fmt.Errorf("vacuum into: %w", err)
	}
	if err := os.Chmod(dst, 0o600); err != nil {
		return fmt.Errorf("chmod copy: %w", err)
	}
	return nil
}
