package main

import (
	"bytes"
	"os"
	"strings"

	pwn "github.com/7Rocky/gopwntools"
)

func GetProcess() *pwn.Conn {
	if len(os.Args) == 1 {
		return pwn.Process("python3", "server.py")
	}

	hostPort := strings.Split(os.Args[1], ":")
	return pwn.Remote(hostPort[0], hostPort[1])
}

func toBlocks(b []byte) [][]byte {
	blocks := make([][]byte, len(b)/16)

	for i := range len(blocks) {
		blocks[i] = b[16*i : 16*i+16]
	}

	return blocks
}

var dict = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

func main() {
	io := GetProcess()
	defer io.Close()

	var pwd []byte
	pwdProg := pwn.Progress("pwd")

	for i := range 16 {
		for _, c := range dict {
			var payload []byte
			payload = append(payload, bytes.Repeat([]byte{'A'}, 15-i)...)
			payload = append(payload, pwd...)
			payload = append(payload, c)
			payload = append(payload, payload...)
			payload = append(payload, bytes.Repeat([]byte{'A'}, 15-i)...)

			io.SendLineAfter([]byte("Choose your path, traveler :: "), []byte{'1'})
			io.SendLineAfter([]byte("[+] Speak thy name, so it may be sealed in the archives :: "), payload)
			io.RecvUntil([]byte("[+] Thy credentials have been sealed in the encrypted scrolls: "))
			dec := pwn.UnHex(strings.TrimSpace(io.RecvLineS()))

			blocks := toBlocks(dec)
			if bytes.Equal(blocks[1], blocks[2]) {
				pwd = append(pwd, c)
				pwdProg.Status(string(pwd))
				break
			}
		}
	}

	for i := range 4 {
		for _, c := range dict {
			var payload []byte
			payload = append(payload, bytes.Repeat([]byte{'A'}, 15-i)...)
			payload = append(payload, pwd...)
			payload = append(payload, c)
			payload = append(payload, payload...)
			payload = append(payload, bytes.Repeat([]byte{'A'}, 15-i)...)

			io.SendLineAfter([]byte("Choose your path, traveler :: "), []byte{'1'})
			io.SendLineAfter([]byte("[+] Speak thy name, so it may be sealed in the archives :: "), payload)
			io.RecvUntil([]byte("[+] Thy credentials have been sealed in the encrypted scrolls: "))
			dec := pwn.UnHex(strings.TrimSpace(io.RecvLineS()))

			blocks := toBlocks(dec)
			if bytes.Equal(blocks[3], blocks[5]) {
				pwd = append(pwd, c)
				pwdProg.Status(string(pwd))
				break
			}
		}
	}

	pwdProg.Success(string(pwd))

	io.SendLineAfter([]byte("Choose your path, traveler :: "), []byte{'2'})
	io.SendLineAfter([]byte("[+] Whisper the sacred incantation to enter the Forbidden Sanctum :: "), pwd)
	io.RecvUntil([]byte("[+] The gates open before you, Keeper of Secrets! "))
	pwn.Success(io.RecvS())
}
