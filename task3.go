/*
Encrypted Server Chit Chat 
The VM you have to connect to has a UDP server running on port 4000. Once connected to this UDP server, send a UDP message with the payload "hello" to receive more information. You will find some sort of encryption(using the AES-GCM cipher). Using the information from the server, write a script to retrieve the flag. Here are some useful thingsto keep in mind:
    sending and receiving data over a network is done in bytes
    the PyCA encryption library and functions takes its inputs as bytes
    AES GCM sends both encrypted plaintext and tag, and the server sends these values sequentially in the form of the encrypted plaintext followed by the tag
This machine may take up to 5 minutes to configure once deployed. Please be patient. 
Use this general approach(use Python3 here as well):
    Use the Python sockets library to create a UDP socket and send the aforementioned packets to the server
    use the PyCA encyption library and follow the instructions from the server
*/

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"time"
)

var reader *bufio.Reader

func read() []byte {
	p := make([]byte, 2048)
	n, _ := reader.Read(p)
	return p[:n]
}

func main() {
	conn, _ := net.Dial("udp", "10.10.211.191:4000")
	defer conn.Close()
	reader = bufio.NewReader(conn)

	fmt.Fprintf(conn, "hello")

	fmt.Println(string(read()))

	fmt.Fprintf(conn, "ready")

	p := read()
	key := p[4:28]
	fmt.Printf("key (len %d): %s\n", len(key), string(key))

	iv := p[32:44]
	fmt.Printf("iv (len %d): %s\n", len(iv), string(iv))

	checksum := hex.EncodeToString(p[104:136])
	fmt.Println("checksum: " + checksum)

	for {
		fmt.Fprintf(conn, "final")
		flag := read()
		fmt.Printf("decoding flag of size %d: %x\n", len(flag), flag)

		fmt.Fprintf(conn, "final")
		tag := read()
		fmt.Printf("with tag of size %d: %x\n", len(tag), tag)

		ciphertext := append(flag, tag...)
		fmt.Printf("final cipher of size %d: %x\n", len(ciphertext), ciphertext)

		block, _ := aes.NewCipher(key)
		aesgcm, _ := cipher.NewGCM(block)

		plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
		if err != nil {
			fmt.Println("failed to decode with err: " + err.Error())
			time.Sleep(time.Second)
			continue
		}

		sha := sha256.Sum256(plaintext)
		hash := hex.EncodeToString(sha[:])
		if hash == checksum {
			fmt.Println(string(plaintext))
			break
		}
		fmt.Println("didn't match checksum")
	}
}