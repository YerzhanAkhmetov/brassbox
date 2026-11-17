package storage

import (
	"sync"

	"github.com/ncruces/go-sqlite3/util/vfsutil"
	"github.com/ncruces/go-sqlite3/vfs"
	"github.com/ncruces/go-sqlite3/vfs/adiantum"
)

// VFSName — Adiantum поверх «сдвинутого» файла: первые HeaderOffset байт
// (открытый заголовок с замками, пакет header) база не трогает.
const VFSName = "brassbox"

// HeaderOffset — где начинается база в файле (= header constant.Size).
// Ровно один блок Adiantum (4 КиБ): страницы базы не сдвигаются внутри блоков.
const HeaderOffset = 4096

var registerOnce sync.Once

// registerVFS — регистрация VFS один раз за процесс (явно, без init()).
func registerVFS() {
	registerOnce.Do(func() {
		vfs.Register(VFSName, adiantum.Wrap(offsetVFS{VFS: vfs.Find(""), off: HeaderOffset}, nil))
	})
}

// offsetVFS сдвигает главный файл базы на off байт; журналы и временные файлы — без сдвига
// (они тоже шифруются Adiantum, заголовка у них нет).
type offsetVFS struct {
	vfs.VFS
	off int64
}

func (o offsetVFS) OpenFilename(name *vfs.Filename, flags vfs.OpenFlag) (vfs.File, vfs.OpenFlag, error) {
	f, flags, err := vfsutil.WrapOpenFilename(o.VFS, name, flags)
	if err != nil || flags&vfs.OPEN_MAIN_DB == 0 {
		return f, flags, err
	}
	return &offsetFile{File: f, off: o.off}, flags, nil
}

type offsetFile struct {
	vfs.File
	off int64
}

func (f *offsetFile) Unwrap() vfs.File { return f.File }

func (f *offsetFile) ReadAt(p []byte, off int64) (int, error) { return f.File.ReadAt(p, off+f.off) }

func (f *offsetFile) WriteAt(p []byte, off int64) (int, error) { return f.File.WriteAt(p, off+f.off) }

func (f *offsetFile) Truncate(size int64) error { return f.File.Truncate(size + f.off) }

func (f *offsetFile) Size() (int64, error) {
	n, err := f.File.Size()
	return max(0, n-f.off), err
}

func (f *offsetFile) LockState() vfs.LockLevel { return vfsutil.WrapLockState(f.File) }

func (f *offsetFile) Pragma(name, value string) (string, error) {
	return vfsutil.WrapPragma(f.File, name, value)
}

func (f *offsetFile) SizeHint(size int64) error { return vfsutil.WrapSizeHint(f.File, size+f.off) }

func (f *offsetFile) HasMoved() (bool, error) { return vfsutil.WrapHasMoved(f.File) }
