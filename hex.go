package encode

import "encoding/hex"

/*
src:待加密数据
num:加密次数
*/
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
