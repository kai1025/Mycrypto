package Mycrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"io"
)

func AesEncryptCBC(origData []byte, key []byte) []byte {
	// 分组秘钥
	// NewCipher该函数限制了输入k的长度必须为16, 24或者32
	block, _ := aes.NewCipher(generateKey(key))
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 补全码
	origData = PKCS7Padding(origData, blockSize)
	// 加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	// 创建数组
	cryted := make([]byte, len(origData))
	// 加密
	blockMode.CryptBlocks(cryted, origData)
	return cryted
}
func AesDecryptCBC(cryted []byte, key []byte) []byte {
	// 分组秘钥
	block, _ := aes.NewCipher(generateKey(key))
	// 获取秘钥块的长度
	blockSize := block.BlockSize()
	// 加密模式
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	// 创建数组
	orig := make([]byte, len(cryted))
	// 解密
	blockMode.CryptBlocks(orig, cryted)
	// 去补全码
	orig = PKCS7UnPadding(orig)
	return orig
}

// ECB
func AesEncryptECB(src []byte, key []byte) (encrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	length := (len(src) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, src)
	pad := byte(len(plain) - len(src))
	for i := len(src); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	// 分组分块加密
	for bs, be := 0, cipher.BlockSize(); bs <= len(src); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return encrypted
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte) {
	cipher, _ := aes.NewCipher(generateKey(key))
	decrypted = make([]byte, len(encrypted))
	//
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	return decrypted[:trim]
}

// AEC加密和解密（CRT模式）
func AesCtrCryptCRT(plainText []byte, key []byte) []byte {

	//指定加密、解密算法为AES，返回一个AES的Block接口对象
	block, _ := aes.NewCipher(generateKey(key))

	//指定计数器,长度必须等于block的块尺寸
	count := []byte("12345678abcdefgh")
	//指定分组模式
	blockMode := cipher.NewCTR(block, count)
	//执行加密、解密操作
	message := make([]byte, len(plainText))
	blockMode.XORKeyStream(message, plainText)

	//返回明文或密文
	return message
}

// CFB
func AesEncryptCFB(origData []byte, key []byte) (encrypted []byte) {
	block, _ := aes.NewCipher(generateKey(key))
	encrypted = make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	return encrypted
}
func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte) {
	block, _ := aes.NewCipher(generateKey(key))
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted
}

// OFB
func AesEncryptOFB(data []byte, key []byte) []byte {
	data = PKCS7Padding(data, aes.BlockSize)
	block, _ := aes.NewCipher(generateKey(key))
	out := make([]byte, aes.BlockSize+len(data))
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil
	}

	stream := cipher.NewOFB(block, iv)
	stream.XORKeyStream(out[aes.BlockSize:], data)
	return out
}

func AesDecryptOFB(data []byte, key []byte) []byte {
	block, _ := aes.NewCipher(generateKey(key))
	iv := data[:aes.BlockSize] //aes.BlockSize=16 偏移量
	data = data[aes.BlockSize:]
	if len(data)%aes.BlockSize != 0 {
		return nil
	}

	out := make([]byte, len(data))
	mode := cipher.NewOFB(block, iv)
	mode.XORKeyStream(out, data)

	out = PKCS7UnPadding(out)
	return out
}

// DES加密方法
func DesEncrypt(origData, key []byte) []byte {
	//将字节秘钥转换成block快

	if len(string(key)) != 8 {
		panic("Error:key length is error，need 8 byte")
	}
	block, _ := des.NewCipher(key)
	//对明文先进行补码操作
	origData = PKCS7Padding(origData, block.BlockSize())
	//设置加密方式
	blockMode := cipher.NewCBCEncrypter(block, key)
	//创建明文长度的字节数组
	crypted := make([]byte, len(origData))
	//加密明文,加密后的数据放到数组中
	blockMode.CryptBlocks(crypted, origData)
	//将字节数组转换成字符串
	return crypted

}

// 解密
func DesDecrypt(src, key []byte) []byte {
	//倒叙执行一遍加密方法
	//将字符串转换成字节数组
	if len(string(key)) != 8 {
		panic("Error:key length is error，need 8 byte")
	}
	//将字节秘钥转换成block快
	block, _ := des.NewCipher(key)
	//设置解密方式
	blockMode := cipher.NewCBCDecrypter(block, key)
	//创建密文大小的数组变量
	origData := make([]byte, len(src))
	//解密密文到数组origData中
	blockMode.CryptBlocks(origData, src)
	//去补码
	origData = PKCS7UnPadding(origData)

	return origData
}

// 解密
func ThriDesDeCrypt(crypted, key []byte) []byte {
	if len(string(key)) != 24 {
		panic("Error:key length is error，need 24 byte")
	}
	//获取block块
	block, _ := des.NewTripleDESCipher(key)
	//创建切片
	context := make([]byte, len(crypted))
	//设置解密方式
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	//解密密文到数组
	blockMode.CryptBlocks(context, crypted)
	//去补码
	context = PKCS7UnPadding(context)
	return context
}

// 加密
func ThriDesEnCrypt(origData, key []byte) []byte {
	if len(string(key)) != 24 {
		panic("Error:key length is error，need 24 byte")
	}
	//获取block块
	block, _ := des.NewTripleDESCipher(key)
	//补码
	origData = PKCS7Padding(origData, block.BlockSize())
	//设置加密方式为 3DES  使用3条56位的密钥对数据进行三次加密
	blockMode := cipher.NewCBCEncrypter(block, key[:8])

	//创建明文长度的数组
	crypted := make([]byte, len(origData))

	//加密明文
	blockMode.CryptBlocks(crypted, origData)

	return crypted

}

// 补码
// AES加密数据块分组长度必须为128bit(byte[16])，密钥长度可以是128bit(byte[16])、192bit(byte[24])、256bit(byte[32])中的任意一个。
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// 去码
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}
