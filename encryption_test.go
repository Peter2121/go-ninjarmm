package ninjarmm

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_encrypt(t *testing.T) {
	t.Run("encrypts and decrypts value", func(t *testing.T) {
		key := "passphrase"
		value := "encrypt this"
		encrypted, err := encrypt(key, value)
		assert.NoError(t, err)
		decrypted, err := decrypt(key, encrypted)
		assert.NoError(t, err)
		assert.Equal(t, value, decrypted)
	})

}
