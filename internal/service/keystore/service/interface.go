package service

// Protector — порт: привязка данных к учётной записи ОС (Keychain / DPAPI — пакет osprotect,
// в тестах — подделка со своим ключом).
type Protector interface {
	Protect(plain []byte) ([]byte, error)
	Unprotect(blob []byte) ([]byte, error)
}
