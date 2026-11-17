package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeAndText(t *testing.T) {
	cases := []struct {
		Name     string
		Err      error
		WantCode Err
		WantText string
	}{
		// ---- свои ошибки ----
		{"Err как есть", ObjectNotFound, ObjectNotFound, "Не найдено."},
		{"Err обёрнут", fmt.Errorf("repo: %w", InvalidRequest), InvalidRequest, "Неверные данные."},
		{"ErrFull", ErrFull{Err: NotImplemented, Desc: "x"}, NotImplemented, "Пока не сделано."},
		{"ErrFull обёрнут", fmt.Errorf("uc: %w", ErrFull{Err: ObjectNotFound}), ObjectNotFound, "Не найдено."},

		// ---- чужие и пустые ----
		{"чужая ошибка", errors.New("disk full"), Internal, texts[Internal]},
		{"код без текста", Err("unknown_code"), Err("unknown_code"), texts[Internal]},
		{"nil", nil, Internal, texts[Internal]},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			assert.Equal(t, c.WantCode, Code(c.Err))
			assert.Equal(t, c.WantText, Text(c.Err))
		})
	}
}

func TestEveryCodeHasText(t *testing.T) {
	for _, e := range []Err{Internal, InvalidRequest, ObjectNotFound, NotImplemented} {
		assert.NotEmpty(t, texts[e], "нет русского текста для %q", e)
	}
}

func TestErrFullUnwrap(t *testing.T) {
	assert.ErrorIs(t, ErrFull{Err: ObjectNotFound, Desc: "id=1"}, ObjectNotFound)
}
