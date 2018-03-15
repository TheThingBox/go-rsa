package rsa

///////////////////////////////////////////////////////////////////////////////
////////////////////////////////        C        //////////////////////////////
///////////////////////////////////////////////////////////////////////////////

/*
  #cgo LDFLAGS: -lssl -lcrypto
  #include <openssl/rsa.h>
  #include <openssl/engine.h>
  #include <openssl/pem.h>
  #include <openssl/err.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
  char last_error_string[2048] = {0};
   RSA* rsa_read_pem_public(char* pem){
     FILE * fp = fopen(pem,"r");
     if(fp == NULL){
       snprintf(last_error_string,sizeof(last_error_string),"open \"%s\" failed",pem);
      return NULL;
     }
     RSA * public_key = RSA_new();
     if (!PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL)){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
      RSA_free(public_key);
      return NULL;
    }
    return public_key;
   }
   RSA* rsa_read_pem_private(char* pem){
     FILE * fp = fopen(pem,"r");
     if(fp == NULL){
       snprintf(last_error_string,sizeof(last_error_string),"open \"%s\" failed",pem);
      return NULL;
     }
     RSA * private_key = RSA_new();
     if (!PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL)){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
      RSA_free(private_key);
      return NULL;
    }
    return private_key;
   }
  int rsa_public_encrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
    RSA* public_key = rsa_read_pem_public(pem);
    if(!public_key){
      return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(public_key));
    int n = RSA_public_encrypt(fromSize,from,(unsigned char *)*to,public_key,padding);
    if (n == -1){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(public_key);
    return n;
  }
  int rsa_private_decrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
    RSA* private_key = rsa_read_pem_private(pem);
    if(!private_key){
      return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(private_key));
    int n = RSA_private_decrypt(fromSize,from,(unsigned char *)*to,private_key,padding);
    if (n == -1){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(private_key);
    return n;
  }
  int rsa_private_encrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
    RSA* private_key = rsa_read_pem_private(pem);
    if(!private_key){
      return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(private_key));
    int n = RSA_private_encrypt(fromSize,from,(unsigned char *)*to,private_key,padding);
    if (n == -1){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(private_key);
    return n;
  }
  int rsa_public_decrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
    RSA* public_key = rsa_read_pem_public(pem);
    if(!public_key){
      return -1;
    }
    *to = (char*)malloc(sizeof(char) * RSA_size(public_key));
    int n = RSA_public_decrypt(fromSize,from,(unsigned char *)*to,public_key,padding);
    if (n == -1){
       snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
    }
    RSA_free(public_key);
    return n;
  }
*/
import "C"
import "math"
import "unsafe"
import "fmt"

const (
  RSA_PKCS1_PADDING = C.RSA_PKCS1_PADDING
  RSA_NO_PADDING    = C.RSA_NO_PADDING
)

func PrivateDecrypt(from []byte, pem string, padding int) ([]byte, error) {
  var to *C.char = nil

  if n := C.rsa_private_decrypt(C.int(len(from)),
    (*C.uchar)(unsafe.Pointer(&from[0])),
    //(*C.uchar)(unsafe.Pointer(&to[0])),
    (**C.char)(unsafe.Pointer(&to)),
    C.CString(pem),
    C.int(padding)); n < 0 {
    return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
  } else {
    m := C.GoBytes(unsafe.Pointer(to), n)
    C.free(unsafe.Pointer(to))
    return m, nil
  }
}

func PublicEncrypt(from []byte, pem string, padding int) ([]byte, error) {
  var to *C.char = nil

  if n := C.rsa_public_encrypt(C.int(len(from)),
    (*C.uchar)(unsafe.Pointer(&from[0])),
    (**C.char)(unsafe.Pointer(&to)),
    //(*C.uchar)(unsafe.Pointer(&to[0])),
    C.CString(pem),
    C.int(padding)); n < 0 {
    return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
  } else {
    m := C.GoBytes(unsafe.Pointer(to), n)
    C.free(unsafe.Pointer(to))
    return m, nil
  }
}

func PublicDecrypt(from []byte, pem string, padding int) ([]byte, error) {
  var to *C.char = nil

  if n := C.rsa_public_decrypt(C.int(len(from)),
    (*C.uchar)(unsafe.Pointer(&from[0])),
    //(*C.uchar)(unsafe.Pointer(&to[0])),
    (**C.char)(unsafe.Pointer(&to)),
    C.CString(pem),
    C.int(padding)); n < 0 {
    return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
  } else {
    m := C.GoBytes(unsafe.Pointer(to), n)
    C.free(unsafe.Pointer(to))
    return m, nil
  }
}

func PrivateEncrypt(from []byte, pem string, padding int) ([]byte, error) {
  var to *C.char = nil

  if n := C.rsa_private_encrypt(C.int(len(from)),
    (*C.uchar)(unsafe.Pointer(&from[0])),
    (**C.char)(unsafe.Pointer(&to)),
    //(*C.uchar)(unsafe.Pointer(&to[0])),
    C.CString(pem),
    C.int(padding)); n < 0 {
    return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
  } else {
    m := C.GoBytes(unsafe.Pointer(to), n)
    C.free(unsafe.Pointer(to))
    return m, nil
  }
}

func Destroy() {
  C.ERR_free_strings()
}

func init() {
  C.ERR_load_crypto_strings()
}

///////////////////////////////////////////////////////////////////////////////
/////////////////////////////        PUBLIC        ////////////////////////////
///////////////////////////////////////////////////////////////////////////////

type Public interface {
  Encrypt(data []byte) ([]byte, error)
  Decrypt(data []byte) ([]byte, error)
}

type rsaPublicKey struct {
  path string
  slice_size int
}

func loadPublicKey(path string, slice_size int) (sshKey Public) {
  sshKey = &rsaPublicKey{path, slice_size}
  return
}

func (pub *rsaPublicKey) Encrypt(data []byte) ([]byte, error) {
  var encrypted []byte
  arrayText := sliceLongData(data, pub.slice_size)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := PublicEncrypt(arrayText[index], pub.path, RSA_PKCS1_PADDING)
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
    tmp, err := PublicDecrypt(arrayText[index], pub.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    decrypted = append(decrypted, tmp...)
  }

  return decrypted, nil
}

///////////////////////////////////////////////////////////////////////////////
/////////////////////////////        PRIVATE        ///////////////////////////
///////////////////////////////////////////////////////////////////////////////

type Private interface {
  Encrypt(data []byte) ([]byte, error)
  Decrypt(data []byte) ([]byte, error)
}

type rsaPrivateKey struct {
  path string
  slice_size int
}

func loadPrivateKey(path string, slice_size int) (sshKey Private) {
  sshKey = &rsaPrivateKey{path, slice_size}
  return
}

func (priv *rsaPrivateKey) Encrypt(data []byte) ([]byte, error) {
  var encrypted []byte
  arrayText := sliceLongData(data, priv.slice_size)
  for index := 0; index < len(arrayText); index++ {
    tmp, err := PrivateEncrypt(arrayText[index], priv.path, RSA_PKCS1_PADDING)
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
    tmp, err := PrivateDecrypt(arrayText[index], priv.path, RSA_PKCS1_PADDING)
    if err != nil {
      return nil, err
    }
    decrypted = append(decrypted, tmp...)
  }

  return decrypted, nil
}

///////////////////////////////////////////////////////////////////////////////
//////////////////////////////        UTILS        ////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func sliceLongData(data []byte, sizeOfSlice int) [][]byte {
	var arrayBytes [][]byte
	var numberOfSlice = int(math.Ceil(float64(len(data)) / float64(sizeOfSlice)))

	for cpt := 0; cpt < numberOfSlice; cpt++ {
		arrayBytes = append(arrayBytes, data[(sizeOfSlice*cpt):int(Min((sizeOfSlice*(cpt+1)), len(data)))])
	}
	return arrayBytes
}

func Min(x, y int) int {
    if x < y {
        return x
    }
    return y
}
