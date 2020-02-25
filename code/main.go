package main

import (
    "flag"
    "fmt"
    "bytes"
    "strings"
    "bufio"
    "os"
    "log"
    "time"
    "strconv"
    "os/exec"
    "io/ioutil"
    "encoding/base64"

    "golang.org/x/crypto/openpgp"
    "golang.org/x/crypto/openpgp/armor"
    "golang.org/x/crypto/openpgp/packet"
)

const dir  = "/etc/ssp/"
const file = "users"

var passphrase string
var settings *bool
var packetConfig *packet.Config

func init(){
    out, err  := exec.Command("dmidecode", "-s", "system-uuid").Output()
    passphrase = base64.StdEncoding.EncodeToString(out)

    if len(passphrase) > 32 {
        passphrase = passphrase[0:32]
    }

    if err != nil {
        log.Fatalf("Cannot execute the command: %s", err)
    }

    packetConfig = &packet.Config{
        DefaultCipher: packet.CipherAES256,
    }

    settings = flag.Bool("config", false, "Add or update a member")

    flag.Parse()

    if err = os.MkdirAll(dir, 0600); err != nil {
        log.Println("Creating folder error!")
    }
}

func main(){
    if *settings {
        if err := config(); err != nil {
            log.Fatalf(err.Error())
        }

        cronjob()
        return
    }

    updatePassword()
}

func config() (err error){
    reader := bufio.NewReader(os.Stdin)
    fmt.Print("Username: ")
    user, _ := reader.ReadString('\n')
    user = strings.TrimSpace(user)

    fmt.Print("Date format(yyyymmddhhmm): ")
    format, _ := reader.ReadString('\n')
    format = strings.TrimSpace(format)

    fmt.Print("Secret key: ")
    fmt.Print("\033[8m")
    password, _ := reader.ReadString('\n')
    fmt.Print("\033[28m")
    password = strings.TrimSpace(password)

    f, err := os.OpenFile(dir + file, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0600)
    if err != nil {
        return
    }
    defer f.Close()

    b, _ := ioutil.ReadAll(f)

    var update bool
    var lines []string

    text := user + "\t" + password + "\t" + format

    if len(b) > 0 {
        var decrypted []string
        if decrypted, err = Decrypt(b, passphrase, packetConfig); err != nil {
            return
        }

        for x := range decrypted {
            tmp := decrypted[x]
            if strings.Contains(decrypted[x], user) {
                tmp    = text
                update = true
            }
            lines = append(lines, tmp)
        }

        if !update {
            lines = append(lines, text)
        }

        text = strings.Join(lines, "\n")
    }

    encrypted, err := Encrypt(text, passphrase, packetConfig)

    if err != nil {
        return
    }

    _ = f.Truncate(0)
    _, _ = f.Seek(0,0)

    if _, err = f.WriteString(encrypted + "\n"); err != nil {
        return
    }

    return
}

func cronjob(){
    f, err := os.OpenFile("/etc/crontab", os.O_APPEND|os.O_RDWR, 0644)
    if err != nil {
        //log.Println(err)
        log.Println("Creating timer and service, wait a second...")
        createService()
        return
    }
    defer f.Close()

    b, _ := ioutil.ReadAll(f)
    cmd := "* * * * *   root   " + os.Args[0]

    if strings.Contains(string(b), cmd) {
        return
    }

    if _, err := f.WriteString(cmd + "\n"); err != nil {
        log.Println(err)
    }
}

func createService(){
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

    f, err := os.OpenFile(path + ".service", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    _ = f.Truncate(0)
    _, _ = f.Seek(0,0)

    if _, err := f.WriteString(service); err != nil {
        log.Println(err)
        return
    }

    f, err = os.OpenFile(path + ".timer", os.O_APPEND|os.O_CREATE|os.O_RDWR, 0644)
    if err != nil {
        return
    }
    defer f.Close()

    _ = f.Truncate(0)
    _, _ = f.Seek(0,0)

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

func updatePassword(){
    data, err := os.Open(dir + file)
    if err != nil {
        log.Fatal(err)
    }
    defer data.Close()

    b, _ := ioutil.ReadAll(data)

    decrypted, err := Decrypt(b, passphrase, packetConfig)
    if err != nil {
        log.Fatalf("Cannot decrypt the file: %s\n", err)
    }

    for x := range decrypted {
        cols := strings.Fields(decrypted[x])
        generatePassword(&cols[1], cols[2])
        changePassword(cols)
    }
}

func generatePassword(password *string, format string){
    var newPassword string

    currentTime := time.Now()
    date := string(currentTime.Format(format))
    maxlen := len(date)
    for x, rune := range *password {
        if x < maxlen {
            z, _ := strconv.Atoi(date[x:x+1])
            newPassword += string(int32(z)+int32(rune))
        } else {
            newPassword += string(int32(rune))
        }
    }

    *password = newPassword
}

func changePassword(fields []string){
    c1 := exec.Command("echo", fields[0] + ":" + fields[1])
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

func Encrypt(plaintext string, password string, packetConfig *packet.Config) (ciphertext string, err error) {
    encbuf := bytes.NewBuffer(nil)

    w, err := armor.Encode(encbuf, "PGP MESSAGE", nil)
    if err != nil {
        return
    }
    defer w.Close()

    pt, err := openpgp.SymmetricallyEncrypt(w, []byte(password), nil, packetConfig)
    if err != nil {
        return
    }
    defer pt.Close()

    _, err = pt.Write([]byte(plaintext))
    if err != nil {
        return
    }

    pt.Close()
    w.Close()
    ciphertext = encbuf.String()

    return
}

func Decrypt(ciphertext []byte, password string, packetConfig *packet.Config) (plaintext []string, err error) {
    decbuf := bytes.NewBuffer(ciphertext)

    armorBlock, err := armor.Decode(decbuf)
    if err != nil {
        return
    }

    failed := false
    prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
        if failed {
            return nil, fmt.Errorf("decryption failed")
        }
        failed = true
        return []byte(password), nil
    }

    md, err := openpgp.ReadMessage(armorBlock.Body, nil, prompt, packetConfig)
    if err != nil {
        return
    }

    text, err := ioutil.ReadAll(md.UnverifiedBody)
    if err != nil {
        return
    }

    plaintext = strings.Split(string(text), "\n")

    return
}