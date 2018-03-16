package rsa

type Public interface {
  Encrypt(data []byte) ([]byte, error)
  Decrypt(data []byte) ([]byte, error)
}

type rsaPublicKey struct {
  path string
  slice_size int
}

func LoadPublicKey(path string, slice_size int) (sshKey Public) {
  sshKey = &rsaPublicKey{path, slice_size}
  return
}

func (pub *rsaPublicKey) Encrypt(data []byte) ([]byte, error) {
  var encrypted []byte
  arrayText := sliceLongData(data, pub.slice_size)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := publicEncrypt(arrayText[index], pub.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    encrypted = append(encrypted, tmp...)
  }

  return encrypted, nil
}

func (pub *rsaPublicKey) Decrypt(data []byte) ([]byte, error) {
  var decrypted []byte
  arrayText := sliceLongData(data, pub.slice_size*2)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := publicDecrypt(arrayText[index], pub.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    decrypted = append(decrypted, tmp...)
  }

  return decrypted, nil
}
