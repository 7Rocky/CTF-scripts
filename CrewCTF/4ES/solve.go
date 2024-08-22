package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"

	"crypto/aes"
	"crypto/sha256"

	"encoding/hex"
)

var chars = []byte("crew_AES*4=$!?")

var charKeys [][]byte
var pt, ct []byte

func main() {
	f, err := os.Open("output.txt")

	if err != nil {
		panic(err)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	scanner.Scan()
	pt, _ = hex.DecodeString(strings.Split(scanner.Text(), " = ")[1])
	scanner.Scan()
	ct, _ = hex.DecodeString(strings.Split(scanner.Text(), " = ")[1])
	scanner.Scan()
	encFlag, _ := hex.DecodeString(strings.Split(scanner.Text(), " = ")[1])

	for _, c1 := range chars {
		for _, c2 := range chars {
			for _, c3 := range chars {
				charKeys = append(charKeys, []byte{c1, c2, c3})
			}
		}
	}

	wxyz := mitm()

	if wxyz == nil {
		fmt.Println("MITM attack failed")
		os.Exit(1)
	}

	w, x, y, z := wxyz[0:3], wxyz[3:6], wxyz[6:9], wxyz[9:12]

	k1 := sha256.Sum256(w)
	k2 := sha256.Sum256(x)
	k3 := sha256.Sum256(y)
	k4 := sha256.Sum256(z)

	if !bytes.Equal(ct, encryptAES(k4[:], encryptAES(k3[:], encryptAES(k2[:], encryptAES(k1[:], pt))))) {
		fmt.Println("Wrong keys found")
		os.Exit(1)
	}

	key := sha256.Sum256(wxyz)

	var FLAG []byte

	for i := 0; i < len(encFlag); i += 16 {
		block := decryptAES(key[:], encFlag[i:i+16])
		FLAG = bytes.Join([][]byte{FLAG, block}, []byte{})
	}

	fmt.Println(string(unpad(FLAG)))
}

func unpad(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}

func encryptAES(key, plaintext []byte) []byte {
	cipher, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, len(plaintext))
	cipher.Encrypt(ciphertext, plaintext)
	return ciphertext
}

func decryptAES(key, ciphertext []byte) []byte {
	cipher, err := aes.NewCipher(key)

	if err != nil {
		panic(err)
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.Decrypt(plaintext, ciphertext)
	return plaintext
}

func mitm() []byte {
	middle := make(map[string][]byte)

	for _, w := range charKeys {
		k1 := sha256.Sum256(w)

		for _, x := range charKeys {
			k2 := sha256.Sum256(x)
			enc := encryptAES(k2[:], encryptAES(k1[:], pt))
			middle[string(enc)] = bytes.Join([][]byte{w, x}, []byte{})
		}
	}

	for _, z := range charKeys {
		k4 := sha256.Sum256(z)

		for _, y := range charKeys {
			k3 := sha256.Sum256(y)
			dec := decryptAES(k3[:], decryptAES(k4[:], ct))

			if wx, ok := middle[string(dec)]; ok {
				return bytes.Join([][]byte{wx, y, z}, []byte{})
			}
		}
	}

	return nil
}
