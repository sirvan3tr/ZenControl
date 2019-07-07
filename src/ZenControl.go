package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	t := time.Now()
	CIPHER_KEY := []byte("s6v9y$B&E)H@McQeThWmZq4t7w!z%C*F")
	fmt.Println(t.Format("2006-01-02-15:04:05"))
	database, _ := sql.Open("sqlite3", "./files.db")
	defer database.Close()

	// Create db if not there already
	//statement, _ := database.Prepare("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, filedir TEXT, status TEXT)")
	//statement.Exec()
	//defer statement.Close()

	// example statements
	//statement, _ = database.Prepare("INSERT INTO files (filename, filedir, status) VALUES (?, ?, ?)")
	//statement.Exec("hww", " ", "decrypted")

	// Query the db

	var ids [][2]int

	rows, _ := database.Query("SELECT id, filename, filedir, status FROM files")
	var id int
	var filename string
	var filedir string
	var status string
	defer rows.Close()

	for rows.Next() {
		rows.Scan(&id, &filename, &filedir, &status)
		fmt.Println(strconv.Itoa(id) + ": " + filename + " " + filedir + " " + status)
		if os.Args[1] == "encrypt" && status == "decrypted" {
			msg, err := ioutil.ReadFile(filedir + filename)
			if err != nil {
				log.Println("File reading error", err)
				return
			}

			// Encryption
			if encrypted, err := encrypt(CIPHER_KEY, msg); err != nil {
				log.Println(err)
			} else {
				err := writer(encrypted, filedir+filename+"_encryptedFile")
				if err != nil {
					log.Println(err)
					return
				}
				log.Printf("ENCRYPTED")

				b := [][2]int{{id, 1}}
				ids = append(ids, b...)

				deleteFile(filedir + filename)

			}

		} else if os.Args[1] == "decrypt" && status == "encrypted" && t.Hour() >= 19 {

			msg, err := ioutil.ReadFile(filedir + filename + "_encryptedFile")
			if err != nil {
				log.Println("File reading error", err)
				return
			}

			if decrypted, err := decrypt(CIPHER_KEY, string(msg)); err != nil {
				log.Println(err)

			} else {
				err := writer(decrypted, filedir+filename)
				if err != nil {
					log.Println(err)
					return
				}
				log.Printf("DECRYPTED")

				b := [][2]int{{id, 2}}
				ids = append(ids, b...)

				deleteFile(filedir + filename + "_encryptedFile")
			}

		}
	}

	var i int
	var stat string

	for i = 0; i < len(ids); i++ {

		if ids[i][1] == 1 {
			stat = "encrypted"
		} else {
			stat = "decrypted"
		}
		_, err := database.Exec("UPDATE files SET status = ? WHERE id = ?", stat, ids[i][0])
		if err != nil {
			log.Fatal(err)
		}
	}

	fmt.Print("Press 'Enter' to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func deleteFile(path string) {
	var err = os.Remove(path)
	if err != nil {
		log.Fatal(err)
		return
	}

	log.Println("==> done deleting file")
	return
}

func encrypt(key []byte, message []byte) (encmess string, err error) {
	plainText := []byte(message)

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//returns to base64 encoded string
	encmess = base64.URLEncoding.EncodeToString(cipherText)
	return
}

func decrypt(key []byte, securemess string) (decodedmess string, err error) {
	cipherText, err := base64.URLEncoding.DecodeString(securemess)
	if err != nil {
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	//IV needs to be unique, but doesn't have to be secure.
	//It's common to put it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(cipherText, cipherText)

	decodedmess = string(cipherText)
	return
}

func writer(cipher string, filename string) (er1 error) {
	f, er1 := os.Create(filename)
	if er1 != nil {
		log.Println(er1)
		return
	}

	n2, er2 := f.Write([]byte(cipher))
	if er2 != nil {
		log.Println(er2)
		f.Close()
		return
	}
	log.Println(n2, "bytes written successfully")
	er3 := f.Close()
	if er3 != nil {
		log.Println(er3)
		return
	}

	return
}
