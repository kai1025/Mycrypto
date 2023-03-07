package encode

import (
	"encoding/base64"
	"fmt"
)

const (
	base64Table = "IJjkKLMNO567PQX12RVW3YZaDEFGbcdefghiABCHlSTUmnopqrxyz04stuvw89+/"
)

var coder = base64.NewEncoding(base64Table)

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
