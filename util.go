package icannclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func ConsoleClearLastLine() {
	fmt.Println("")
	fmt.Print("\033[1A\033[K")
}
func encryptEnvVars(envFile string) error {
	if !FileOrDirExists(envFile) {
		return fmt.Errorf("file: %s does not exist", envFile)
	}
	saltValuePlain := ""

	envSaltValue, envSaltValueExist := os.LookupEnv("SALT_PHRASE")
	if envSaltValueExist && envSaltValue != "" {
		// Salt phrase is set on the machine
		saltValuePlain = envSaltValue
	}

	b, err := ioutil.ReadFile(envFile)
	if err == nil {
		lines := strings.Split(string(b), "\n")

		if saltValuePlain == "" {
			// Look for the salt value in the file
			for i := 0; i < len(lines); i++ {
				lines[i] = strings.Trim(lines[i], " ")
				if lines[i] == "" || strings.HasPrefix(lines[i], "#") {
					continue
				}
				v := strings.Split(lines[i], "=")
				key := v[0]
				value := v[1]
				if key == "SALT_PHRASE" {
					saltValuePlain = value
					break
				}
			}
		}
		if saltValuePlain == "" {
			// still blank; salt value is needed, whether set in
			// file or exported on the machine-level
			return errors.New("SALT_PHRASE is blank")
		}
		// if saltValuePlain is already encrypted, bail out
		_, err := hex.DecodeString(saltValuePlain)
		if err == nil {
			return nil
		}

		m := make(map[string]string, 1)

		// Encrypt the salt value; with blank salt phrase.
		enc, err := EncryptLight([]byte(saltValuePlain), "")
		if err != nil {
			// stop the show if there is any error on
			// encryption
			log.Fatal(err)
		}
		s := hex.EncodeToString(enc)
		m["SALT_PHRASE"] = s

		// Now the rest
		for i := 0; i < len(lines); i++ {
			lines[i] = strings.Trim(lines[i], " ")
			if lines[i] == "" || strings.HasPrefix(lines[i], "#") {
				continue
			}
			v := strings.Split(lines[i], "=")
			key := v[0]
			value := v[1]
			if key == "SALT_PHRASE" {
				continue
			}
			enc, err := EncryptLight([]byte(value), saltValuePlain)
			if err != nil {
				// stop the show if there is any error on
				// encryption
				log.Fatal(err)
			}
			s := hex.EncodeToString(enc)
			m[key] = s
		}
		var newLines []string
		for i := 0; i < len(lines); i++ {
			lines[i] = strings.Trim(lines[i], " ")
			if lines[i] == "" || strings.HasPrefix(lines[i], "#") {
				newLines = append(newLines, lines[i])
				continue
			}
			v := strings.Split(lines[i], "=")
			key := v[0]
			str := fmt.Sprintf("%s=%s", key, m[key])

			newLines = append(newLines, str)
		}
		f, err := os.Create(envFile)
		if err != nil {
			// stop the show; can't re-create the file!
			log.Fatal(err)
		}
		defer f.Close()

		for _, line := range newLines {
			_, err := f.WriteString(line + "\n")
			if err != nil {
				// stop the show; must be able to write to the env file
				log.Fatal(err)
			}
		}
	} else {
		// sotp the show if there an error reading the env file.
		log.Fatal(err)
	}

	return nil
}

// SetEnvFromFile read target key/val from the icann.env
// file. It encrypts plain-text values before returning.
func SetEnvFromFile(envFile string) error {

	if !FileOrDirExists(envFile) {
		return fmt.Errorf("%s does not exist", envFile)
	}

	encryptEnvVars(envFile)

	b, err := ioutil.ReadFile(envFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	saltValue := ""

	for i := 0; i < len(lines); i++ {
		lines[i] = strings.TrimSpace(lines[i])
		if lines[i] == "" || strings.HasPrefix(lines[i], "#") {
			continue
		}
		pos := strings.Index(lines[i], "=")
		if pos < 0 {
			continue
		}
		key := strings.TrimSpace(lines[i][:pos])
		value := strings.TrimSpace(lines[i][pos+1:])
		if key == "SALT_PHRASE" {
			bx, err := hex.DecodeString(value)
			if err != nil {
				log.Fatal(err)
			}
			bValue, err := DecryptLight(bx, "")
			if err != nil {
				log.Fatal(err)
			}
			saltValue = string(bValue)
			os.Setenv(key, string(bValue))
		} else {
			bx, err := hex.DecodeString(value)
			if err != nil || len(value) < 13 {
				// as-is not encrypted
				os.Setenv(key, value)
				continue
			}
			bValue, _ := DecryptLight(bx, saltValue)
			strValue := string(bValue)
			os.Setenv(key, strValue)
		}
	}

	return nil
}

func EncryptLight(data []byte, passphrase string) ([]byte, error) {
	block, _ := aes.NewCipher([]byte(CreateHash(passphrase)))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// CreateHash --
func CreateHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

// DecryptLight --d
func DecryptLight(data []byte, passphrase string) ([]byte, error) {
	var plaintext []byte
	if len(data) == 0 {
		return nil, errors.New("data is empty; nothing to decrypt")
	}
	key := []byte(CreateHash(passphrase))
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if nonceSize < 1 || len(data) < nonceSize {
		return data, nil
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// formatDuration returns the time portion of time in format: hh:mm:ss.
// This has originally been suggested in a public netowrk article on
// https://stackoverflow.com/questions/47341278/how-to-format-a-duration,
// which was written to hold only hh:mm. This function has modified
// it to also hold seconds (hh:mm:ss).
func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// getNeutralDate gets padded data from the left in
// the format: YYYYMMDD.
func getNeutralDate(t time.Time) string {
	return fmt.Sprintf("%d%02d%02d", time.Now().Year(), time.Now().Month(), time.Now().Day())
}

func RemoveItemFromIntArry(s []interface{}, i int) []interface{} {
	s[len(s)-1], s[i] = s[i], s[len(s)-1]
	return s[:len(s)-1]
}

// FileOrDirExists checks to see if a file or dir exist.
// Note that os.Stat(path) works for any path (file or
// directory).
func FileOrDirExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)

	return !os.IsNotExist(err)
}

// getFreeDiskSpace reads the output of df -h /
// and returned the free disk-space on the system in GB (linux only).
func getFreeDiskSpace() float64 {

	var freedksp float64

	lsCmd := exec.Command("bash", "-c", " df -h /")
	lsOut, _ := lsCmd.Output()
	values := strings.Split(string(lsOut), "\n")

	for i := 1; i < len(values); i++ {
		oneLine := values[i]

		v := strings.Split(oneLine, " ")

		src := v[0]

		isDev := strings.HasPrefix(src, "/dev")
		if !isDev || strings.Contains(src, "/loop") {
			continue
		}

		for i := 0; i < 5; i++ {
			oneLine = strings.ReplaceAll(oneLine, "  ", " ")
		}
		v = strings.Split(oneLine, " ")
		avail := v[3]
		avail = avail[:len(avail)-1]
		freedksp, _ = strconv.ParseFloat(avail, 64)
		if v[3][len(v[3])-1:] == "T" {
			freedksp = freedksp * 1024
		}
		break
	}

	return freedksp
}

// itemExists is used to check for duplicates. It returns true
// if the element already exists in the array.
func itemExists(arry []interface{}, item interface{}) bool {
	for i := 0; i < len(arry); i++ {
		if arry[i] == item {
			return true
		}
	}
	return false
}

// roundNumber rounds a number to a target decimail point.
func roundNumber(n float64, percision uint32) float64 {
	return math.Round(n*math.Pow(10, float64(percision))) / math.Pow(10, float64(percision))
}

// getMaxFreeDiskForZoneFile return the amount of
// free-disk-space reported by the system minus 10%
func getMaxFreeDiskForZoneFile() float64 {

	freeDisk := getFreeDiskSpace()
	workbenchRatio := freeDisk - (freeDisk * 0.1)

	return workbenchRatio
}
