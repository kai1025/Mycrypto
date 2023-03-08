package Mycrypto

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	base64Table = "IJjkKLMNO567PQX12RVW3YZaDEFGbcdefghiABCHlSTUmnopqrxyz04stuvw89+/"
)

var coder = base64.NewEncoding(base64Table)

/*
src:待加密数据
num:加密次数
*/

func Base64Encode(src []byte, num int) []byte { //编码
	if num >= 1 {
		for i := 0; i < num; i++ {
			src = []byte(coder.EncodeToString(src))
		}
	} else {
		fmt.Println("error:num<1")
	}
	return src
}

func Base64Decode(src []byte, num int) []byte { //解码

	if num >= 1 {
		for i := 0; i < num; i++ {
			src, _ = coder.DecodeString(string(src))
		}
	} else {
		fmt.Println("error:num<1")
	}
	return src
}
func HexDecode(src []byte, num int) []byte {
	for i := 0; i < num; i++ {
		src, _ = hex.DecodeString(string(src))
	}
	return src
}
func HexEncode(src []byte, num int) []byte {
	for i := 0; i < num; i++ {
		src = []byte(hex.EncodeToString(src))
	}
	return src
}

func XorCrypto(data []byte, keywords string) (out []byte) {
	out = make([]byte, len(data))

	for i, v := range data {
		out[i] = v ^ keywords[i%len(keywords)]
	}
	return out
}

func NonCrypto(data []byte) (out []byte) {
	out = make([]byte, len(data))

	for i, v := range data {
		out[i] = ^v
	}
	return out
}
