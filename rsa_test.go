package main

import (
	"encoding/base64"
	"github.com/TheThingBox/go-rsa"
	"fmt"
	"os"
)

func main() {
	///////////////////////////////////////////////////////////////// INIT

	priv := rsa.LoadPrivateKey("./private.pem", 128)
	pub := rsa.LoadPublicKey("./public.pem", 128)

	message := []byte("hello")
	fmt.Printf("Original message: %v\n\n", string(message))

	///////////////////////////////////////////////////////////////// PRIV ENCRYPT

	priv_encrypted, err := priv.Encrypt(message)
	if err != nil {
		fmt.Printf("could not priv_encrypt request : %v\n", err)
		os.Exit(1)
	}
	sig1 := []byte(base64.StdEncoding.EncodeToString(priv_encrypted))
	fmt.Printf("priv_encrypted :\n%v\n\n", string(sig1))

	///////////////////////////////////////////////////////////////// PUB ENCRYPT

	pub_encrypted, err := pub.Encrypt(priv_encrypted)
	if err != nil {
		fmt.Printf("could not pub_encrypt request: %v\n", err)
		os.Exit(1)
	}
	sig2 := []byte(base64.StdEncoding.EncodeToString(pub_encrypted))
	fmt.Printf("pub_encrypted :\n%v\n\n", string(sig2))

	fmt.Printf("\n-----------------------\n\n")
	///////////////////////////////////////////////////////////////// PRIV DECRYPT

	priv_decrypted, err := priv.Decrypt(pub_encrypted)
	if err != nil {
		fmt.Printf("could not priv_decrypt request : %v\n", err)
		os.Exit(1)
	}
	sig3 := []byte(base64.StdEncoding.EncodeToString(priv_decrypted))
	fmt.Printf("priv_decrypted :\n%v\n\n", string(sig3))

	///////////////////////////////////////////////////////////////// PUB DECRYPT

	pub_decrypted, err := pub.Decrypt(priv_decrypted)
	if err != nil {
		fmt.Printf("could not pub_decrypt request: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("message :\n%v\n", string(pub_decrypted))
}
