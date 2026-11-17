package service

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"brassbox/internal/service/crypto"
	localConstant "brassbox/internal/service/vault/service/constant"
	"brassbox/internal/storage"
)

var backupName = regexp.MustCompile(localConstant.BackupPattern)

// backupFolder — backups/<имя базы без .pwv>.
func (s *Service) backupFolder(vaultPath string) string {
	name := strings.TrimSuffix(filepath.Base(vaultPath), filepath.Ext(vaultPath))
	return filepath.Join(s.backupDir, name)
}

// backup — автокопия: VACUUM INTO во временный файл → заголовок → имя по времени.
// Существующие файлы не перезаписываются: занято имя — суффикс -2, -3…
func (s *Service) backup(ctx context.Context, o *opened, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir backups: %w", err)
	}
	tmp := filepath.Join(dir, localConstant.BackupTmp+hex.EncodeToString(crypto.Random(6))+localConstant.BackupExt)
	defer func() { _ = os.Remove(tmp) }() // после переименования его уже нет

	if err := storage.VacuumInto(ctx, o.db, tmp, o.dek); err != nil {
		return "", err
	}
	if err := s.header.Clone(o.path, tmp); err != nil {
		return "", err
	}

	stamp := s.now().Format(localConstant.BackupLayout)
	for i := 1; i <= 100; i++ {
		name := stamp
		if i > 1 {
			name += "-" + strconv.Itoa(i)
		}
		dst := filepath.Join(dir, name+localConstant.BackupExt)
		if _, err := os.Stat(dst); !errors.Is(err, fs.ErrNotExist) {
			continue
		}
		// Rename, а не Link: папка копий может быть на флешке (FAT/exFAT без жёстких ссылок).
		if err := os.Rename(tmp, dst); err != nil {
			return "", fmt.Errorf("rename backup: %w", err)
		}
		return dst, nil
	}
	return "", fmt.Errorf("backup name %s: too many copies in one second", stamp)
}

// backups — имена автокопий в папке, новые первыми.
func backups(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read backups: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && backupName.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	return names, nil
}

// backedUpToday — есть ли сегодняшняя автокопия.
func (s *Service) backedUpToday(dir string) bool {
	names, err := backups(dir)
	if err != nil {
		return false
	}
	today := s.now().Format(localConstant.BackupDay)
	for _, n := range names {
		if strings.HasPrefix(n, today) {
			return true
		}
	}
	return false
}

// rotate — оставить keep новых автокопий, старые удалить (только файлы по шаблону имени).
func (s *Service) rotate(dir string) error {
	names, err := backups(dir)
	if err != nil {
		return err
	}
	var errList []error
	for _, n := range names[min(s.keep, len(names)):] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			errList = append(errList, err)
		}
	}
	return errors.Join(errList...)
}
