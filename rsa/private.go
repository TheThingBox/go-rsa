package rsa

type Private interface {
  Encrypt(data []byte) ([]byte, error)
  Decrypt(data []byte) ([]byte, error)
}

type rsaPrivateKey struct {
  path string
  slice_size int
}

func LoadPrivateKey(path string, slice_size int) (sshKey Private) {
  sshKey = &rsaPrivateKey{path, slice_size}
  return
}

func (priv *rsaPrivateKey) Encrypt(data []byte) ([]byte, error) {
  var encrypted []byte
  arrayText := sliceLongData(data, priv.slice_size)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := privateEncrypt(arrayText[index], priv.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    encrypted = append(encrypted, tmp...)
  }

  return encrypted, nil
}

func (priv *rsaPrivateKey) Decrypt(data []byte) ([]byte, error) {
  var decrypted []byte
  arrayText := sliceLongData(data, priv.slice_size*2)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := privateDecrypt(arrayText[index], priv.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    decrypted = append(decrypted, tmp...)
  }

  return decrypted, nil
}
