package main

import (
	"flag"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	statusEncrypted = "encrypted"
	statusDecrypted = "decrypted"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	command := os.Args[1]
	switch command {
	case "encrypt", "decrypt":
	default:
		printUsage()
		os.Exit(2)
	}

	flagSet := flag.NewFlagSet(command, flag.ExitOnError)
	dbPath := flagSet.String("db", "./files.db", "path to sqlite database")
	keyStr := flagSet.String("key", "", "encryption key (16/24/32 bytes). If empty, uses ZENCONTROL_KEY env")
	unlockHour := flagSet.Int("unlock-hour", 19, "local hour (0-23) after which decryption is allowed")
	pause := flagSet.Bool("pause", false, "pause for Enter before exit")
	allowLegacy := flagSet.Bool("allow-legacy", false, "allow legacy AES-CFB decrypt for older files")
	flagSet.Parse(os.Args[2:])

	if *unlockHour < 0 || *unlockHour > 23 {
		log.Fatalf("invalid -unlock-hour: %d (expected 0-23)", *unlockHour)
	}

	if *keyStr == "" {
		*keyStr = os.Getenv("ZENCONTROL_KEY")
	}
	if *keyStr == "" {
		log.Fatal("missing encryption key; provide -key or set ZENCONTROL_KEY")
	}
	key := []byte(*keyStr)
	if err := validateKeyLength(key); err != nil {
		log.Fatal(err)
	}

	now := time.Now()
	log.Printf("time=%s", now.Format(time.RFC3339))

	database, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()
	if err := database.Ping(); err != nil {
		log.Fatalf("ping db: %v", err)
	}
	if err := ensureTable(database); err != nil {
		log.Fatalf("ensure table: %v", err)
	}

	rows, err := database.Query("SELECT id, filename, filedir, status FROM files")
	if err != nil {
		log.Fatalf("query files: %v", err)
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var filename string
		var filedir string
		var status string
		if err := rows.Scan(&id, &filename, &filedir, &status); err != nil {
			log.Printf("scan row: %v", err)
			continue
		}

		updatedStatus, updated, err := processFile(command, key, filename, filedir, status, now, *unlockHour, *allowLegacy)
		if err != nil {
			log.Printf("id=%d file=%s: %v", id, filename, err)
			continue
		}
		if !updated {
			continue
		}

		if err := updateStatus(database, id, updatedStatus); err != nil {
			log.Printf("update status id=%d: %v", id, err)
		}
	}
	if err := rows.Err(); err != nil {
		log.Fatalf("rows error: %v", err)
	}

	if *pause {
		fmt.Print("Press 'Enter' to continue...")
		_, _ = fmt.Fscanln(os.Stdin)
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  ZenControl encrypt [flags]")
	fmt.Println("  ZenControl decrypt [flags]")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  -db           path to sqlite database (default ./files.db)")
	fmt.Println("  -key          encryption key (16/24/32 bytes); or set ZENCONTROL_KEY")
	fmt.Println("  -unlock-hour  local hour (0-23) after which decryption is allowed (default 19)")
	fmt.Println("  -pause        pause for Enter before exit")
	fmt.Println("  -allow-legacy allow legacy AES-CFB decrypt for older files")
}

func ensureTable(db *sql.DB) error {
	_, err := db.Exec("CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, filename TEXT, filedir TEXT, status TEXT)")
	return err
}

func updateStatus(db *sql.DB, id int, status string) error {
	_, err := db.Exec("UPDATE files SET status = ? WHERE id = ?", status, id)
	return err
}

func processFile(command string, key []byte, filename string, filedir string, status string, now time.Time, unlockHour int, allowLegacy bool) (string, bool, error) {
	plainPath := filepath.Join(filedir, filename)
	encryptedPath := filepath.Join(filedir, filename+"_encryptedFile")

	switch command {
	case "encrypt":
		if status != statusDecrypted {
			return "", false, nil
		}

		msg, err := os.ReadFile(plainPath)
		if err != nil {
			return "", false, fmt.Errorf("read file: %w", err)
		}

		encrypted, err := encrypt(key, msg)
		if err != nil {
			return "", false, fmt.Errorf("encrypt: %w", err)
		}

		if err := writeFileAtomic(encryptedPath, []byte(encrypted), 0600); err != nil {
			return "", false, fmt.Errorf("write encrypted file: %w", err)
		}

		if err := deleteFile(plainPath); err != nil {
			return "", false, fmt.Errorf("delete plaintext: %w", err)
		}

		log.Printf("encrypted %s", plainPath)
		return statusEncrypted, true, nil

	case "decrypt":
		if status != statusEncrypted {
			return "", false, nil
		}
		if now.Hour() < unlockHour {
			log.Printf("skip %s (locked until %02d:00 local time)", filename, unlockHour)
			return "", false, nil
		}

		msg, err := os.ReadFile(encryptedPath)
		if err != nil {
			return "", false, fmt.Errorf("read encrypted file: %w", err)
		}

		decrypted, err := decrypt(key, string(msg))
		if err != nil {
			if allowLegacy {
				legacyPlain, legacyErr := decryptLegacyCFB(key, string(msg))
				if legacyErr != nil {
					return "", false, fmt.Errorf("decrypt failed (gcm=%v, legacy=%v)", err, legacyErr)
				}
				decrypted = legacyPlain
				log.Printf("legacy decrypt used for %s", encryptedPath)
			} else {
				return "", false, fmt.Errorf("decrypt: %w", err)
			}
		}

		if err := writeFileAtomic(plainPath, []byte(decrypted), 0600); err != nil {
			return "", false, fmt.Errorf("write plaintext: %w", err)
		}
		if err := deleteFile(encryptedPath); err != nil {
			return "", false, fmt.Errorf("delete encrypted: %w", err)
		}

		log.Printf("decrypted %s", plainPath)
		return statusDecrypted, true, nil
	default:
		return "", false, fmt.Errorf("unknown command: %s", command)
	}
}

func deleteFile(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return nil
}

func validateKeyLength(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid key length %d (must be 16, 24, or 32 bytes)", len(key))
	}
}

func encrypt(key []byte, message []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nil, nonce, message, nil)
	payload := append(nonce, cipherText...)
	return base64.StdEncoding.EncodeToString(payload), nil
}

func decrypt(key []byte, securemess string) (string, error) {
	payload, err := decodeBase64(securemess)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce := payload[:gcm.NonceSize()]
	cipherText := payload[gcm.NonceSize():]
	plainText, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(plainText), nil
}

func decryptLegacyCFB(key []byte, securemess string) (string, error) {
	cipherText, err := decodeBase64(securemess)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(cipherText) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	return string(cipherText), nil
}

func decodeBase64(value string) ([]byte, error) {
	if data, err := base64.StdEncoding.DecodeString(value); err == nil {
		return data, nil
	}
	return base64.URLEncoding.DecodeString(value)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		_ = os.Remove(tmpName)
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}
