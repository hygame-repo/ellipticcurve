package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"ellipticcurve/ecdsa"
	"ellipticcurve/privatekey"
	"ellipticcurve/publickey"
	"ellipticcurve/signature"
)

const testPublicKey = "-----BEGIN PUBLIC KEY-----\n" +
	"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEcHvKc1cg/MpX5chv0Nqrb+kTxMlhwydQ\n" +
	"8zoEiVpHSPsQwhRTE9EwkcMsJh2DesqGcob6IxTOxsUoIsvJlbHIKA==\n" +
	"-----END PUBLIC KEY-----\n"

const testPrivateKey = "-----BEGIN EC PRIVATE KEY-----\n" +
	"MHUCAQEEIXvYCYHVm0Gal5SMtMeCYd7yLbYnrSqyLbqSaTNVrvrh/6AHBgUrgQQA\n" +
	"CqFEA0IABHB7ynNXIPzKV+XIb9Daq2/pE8TJYcMnUPM6BIlaR0j7EMIUUxPRMJHD\n" +
	"LCYdg3rKhnKG+iMUzsbFKCLLyZWxyCg=\n" +
	"-----END EC PRIVATE KEY-----\n"

func printObject(obj interface{}) {
	jsonData, err := json.Marshal(obj)
	if err != nil {
		fmt.Println("JSON serialiation error:", err)
		return
	}
	fmt.Println(string(jsonData))
}

// sort param and generate md5
func sortedAndGenerateMD5(paramMap map[string]interface{}) (string, error) {
	fmt.Println("sortedAndGenerateMD5")
	fmt.Print("Origin params:")
	printObject(paramMap)

	keys := make([]string, len(paramMap))
	i := 0
	for k := range paramMap {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	sortedParamMap := make(map[string]interface{})
	for _, k := range keys {
		sortedParamMap[k] = paramMap[k]
	}

	fmt.Print("Sorted params:")
	printObject(sortedParamMap)

	jsonSortedParam, err := json.Marshal(sortedParamMap)
	if err != nil {
		return "", err
	}

	hash := md5.Sum([]byte(jsonSortedParam))
	md5String := hex.EncodeToString(hash[:])

	fmt.Println("MD5 string:", md5String)
	return md5String, nil
}

// generate sign
func generateSign(paramMap map[string]interface{}, privateKeyPem string) (string, error) {
	md5String, err := sortedAndGenerateMD5(paramMap)
	if err != nil {
		return "", err
	}

	privateKey := privatekey.FromPem(privateKeyPem)
	signature := ecdsa.Sign(md5String, &privateKey)
	fmt.Println("Signature:", signature.ToBase64())

	return signature.ToBase64(), nil
}

// verify
func verify(message string, sign string, publicKeyPem string) bool {
	publicKey := publickey.FromPem(publicKeyPem)
	signature := signature.FromBase64(sign)
	return ecdsa.Verify(message, signature, &publicKey)
}

func main() {
	fmt.Println("HQPay Demo")
	testParamMap := map[string]interface{}{
		"externalOrderNo": "10009239548584548",
		"expiration":      3600,
		"amount":          100,
	}
	signature, err := generateSign(testParamMap, testPrivateKey)
	if err != nil {
		fmt.Println("generateSign err", err)
		return
	}

	md5String, err := sortedAndGenerateMD5(testParamMap)
	if err != nil {
		fmt.Println("sortedAndGenerateMD5 err", err)
		return
	}

	result := verify(md5String, signature, testPublicKey)
	fmt.Println("verify result:", result)
}
