package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/armor"
)

const (
	appVersion = "1.1.0"
	dir        = "/etc/ssp/"
	file       = "users"
	maxPassLen = 32
)

var (
	passphrase string
	settings   *bool
	identity   age.Identity
)

func init() {
	out, err := exec.Command("cat", "/sys/class/dmi/id/product_uuid").Output()
	passphrase = base64.StdEncoding.EncodeToString(out)

	if len(passphrase) > maxPassLen {
		passphrase = passphrase[:maxPassLen]
	}

	if err != nil {
		fmt.Printf("Cannot execute the command, you need root privileges")
		os.Exit(0)
	}

	settings = flag.Bool("config", false, "Add or update a member")
	version := flag.Bool("v", false, "Prints current SSP version")

	flag.Parse()

	if err = os.MkdirAll(dir, 0600); err != nil {
		log.Println("Creating folder error!")
	}

	if *version {
		fmt.Printf("Shoulder Surfing Protector - Version %s\n", appVersion)
		os.Exit(0)
	}

	identity, err = age.NewScryptIdentity(passphrase)
	if err != nil {
		log.Fatalf("Failed to create age identity: %v", err)
	}
}

func main() {
	if *settings {
		if err := config(); err != nil {
			log.Fatalf(err.Error())
		}

		cronjob()
		return
	}

	updatePassword()
}

func config() (err error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	user, _ := reader.ReadString('\n')
	user = strings.TrimSpace(user)

	fmt.Print("Date format(yyyymmddhhii): ")
	format, _ := reader.ReadString('\n')
	stdToGo(&format)

	fmt.Print("Secret key: ")
	fmt.Print("\033[8m")
	password, _ := reader.ReadString('\n')
	fmt.Print("\033[28m")
	password = strings.TrimSpace(password)

	f, err := os.OpenFile(dir+file, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return
	}
	defer f.Close()

	b, _ := io.ReadAll(f)

	var update bool
	var lines []string

	text := user + "\t" + password + "\t" + format

	if len(b) > 0 {
		var decrypted []string
		if decrypted, err = Decrypt(b); err != nil {
			return
		}

		for x := range decrypted {
			tmp := decrypted[x]
			if strings.Contains(decrypted[x], user) {
				tmp = text
				update = true
			}
			lines = append(lines, tmp)
		}

		if !update {
			lines = append(lines, text)
		}

		text = strings.Join(lines, "\n")
	}

	encrypted, err := Encrypt(text)

	if err != nil {
		return
	}

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)

	if _, err = f.WriteString(encrypted + "\n"); err != nil {
		return
	}

	return
}

func cronjob() {
	f, err := os.OpenFile("/etc/crontab", os.O_APPEND|os.O_RDWR, 0644)
	if err != nil {
		//log.Println(err)
		log.Println("Creating timer and service, wait a second...")
		createService()
		return
	}
	defer f.Close()

	b, _ := io.ReadAll(f)
	cmd := "* * * * *   root   " + os.Args[0]

	if strings.Contains(string(b), cmd) {
		return
	}

	if _, err := f.WriteString(cmd + "\n"); err != nil {
		log.Println(err)
	}
}

func stdToGo(format *string) {
	x := strings.TrimSpace(*format)
	x = strings.Replace(x, "yyyy", "2006", -1)
	x = strings.Replace(x, "mm", "01", -1)
	x = strings.Replace(x, "dd", "02", -1)
	x = strings.Replace(x, "hh", "15", -1)
	*format = strings.Replace(x, "ii", "04", -1)
}

func createService() {
	service := `[Unit]
Description=Shoulder Surfing Protector service
After=systemd-sysusers.service

[Service]
Type=simple
ExecStart=/bin/sh -c "` + os.Args[0] + `"`
	timer := `[Unit]
Description=1min timer

[Timer]
OnCalendar=*:0/1:0
Persistent=yes
Unit=ssp.service
AccuracySec=1

[Install]
WantedBy=default.target`

	path := "/usr/lib/systemd/system/ssp"

	f, err := os.OpenFile(path+".service", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)

	if _, err := f.WriteString(service); err != nil {
		log.Println(err)
		return
	}

	f, err = os.OpenFile(path+".timer", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	_ = f.Truncate(0)
	_, _ = f.Seek(0, 0)

	if _, err := f.WriteString(timer); err != nil {
		log.Println(err)
		return
	}

	cmd := exec.Command("systemctl", "enable", "--now", "ssp.timer")
	err = cmd.Run()

	if err != nil {
		log.Fatalf("Cannot execute the command: %s", err)
	}
}

func updatePassword() {
	data, err := os.Open(dir + file)
	if err != nil {
		log.Fatal(err)
	}
	defer data.Close()

	b, _ := io.ReadAll(data)

	decrypted, err := Decrypt(b)
	if err != nil {
		log.Fatalf("Cannot decrypt the file: %s\n", err)
	}

	for x := range decrypted {
		cols := strings.Fields(decrypted[x])
		generatePassword(&cols[1], cols[2])
		changePassword(cols)
	}
}

func generatePassword(password *string, format string) {
	var newPassword string

	currentTime := time.Now()
	date := string(currentTime.Format(format))
	maxlen := len(date)
	for x, rune := range *password {
		if x < maxlen {
			z, _ := strconv.Atoi(date[x : x+1])
			newPassword += string(int32(z) + int32(rune))
		} else {
			newPassword += string(int32(rune))
		}
	}

	*password = newPassword
}

func changePassword(fields []string) {
	c1 := exec.Command("echo", fields[0]+":"+fields[1])
	c2 := exec.Command("/usr/sbin/chpasswd")

	c2.Stdin, _ = c1.StdoutPipe()
	c2.Stdout = os.Stdout

	err1 := c2.Start()
	if err1 != nil {
		log.Fatal(err1)
	}

	err2 := c1.Run()
	if err2 != nil {
		log.Fatal(err2)
	}

	err3 := c2.Wait()
	if err3 != nil {
		fmt.Println("User not found!")
		log.Println(err3)
	}
}

func Encrypt(plaintext string) (ciphertext string, err error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)

	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return "", err
	}

	_, err = io.WriteString(w, plaintext)
	if err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}

	armorWriter.Close()
	return buf.String(), nil
}

func Decrypt(ciphertext []byte) (plaintext []string, err error) {
	armorReader := armor.NewReader(bytes.NewReader(ciphertext))

	r, err := age.Decrypt(armorReader, identity)
	if err != nil {
		return nil, err
	}

	text, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(text), "\n"), nil
}
