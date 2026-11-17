package service

// headerI — порт: заголовок файла (пакет header).
type headerI interface {
	Create(path string, dek, master []byte, password string) error
	Verify(path string, dek []byte) error
	Clone(src, dst string) error
}
