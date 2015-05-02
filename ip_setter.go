// auth-ip
//
// Dieses Skript dient der Authentifizierung eines Users und der Speicherung seiner
// IP-Adresse in einer Datei und den Aufruf eines iptables-Skripts, das die
// Adressen in iptables freigibt

package main

import (
	"bufio"
	"code.google.com/p/gcfg"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// JSON-Antwortstruktur
type Response struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	UserName string `json:"userName,omitempty"`
}

// Struktur für die Konfiguration
type Config struct {
	IPTables struct {
		Runscript   string
		RunWithSudo bool
		AddressDir  string
	}
	Users struct {
		UserFile string
	}
}

// Struktur der User-Datei
type User struct {
	UserName   string `json:"userName"`
	Password   string `json:"password"`
	Privileges int    `json:"priv"`
}
type Users struct {
	Users []User `json:"users"`
}

var cfg Config

func getIP(w http.ResponseWriter, r *http.Request) {
	// CORS-Support
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	ip := net.ParseIP(r.Header["X-Forwarded-For"][len(r.Header["X-Forwarded-For"])-1])

	var json_response []byte
	if user, privileges := getUser(w, r); privileges > -1 {
		if privileges > 0 {
			saveAddress(user.UserName, ip.String())
			updateIpTables()
			json_response, _ = json.Marshal(Response{0, "Erfolgreich gesetzt", ""})
			fmt.Fprintf(w, string(json_response))
			return
		}
		json_response, _ = json.Marshal(Response{-30, "Nicht genügend Rechte", ""})
		fmt.Fprintf(w, string(json_response))
		return
	}
}

// Authentifiziert einen Benutzer
func authenticate(userName string, password string) (User, bool) {
	// erst mal die Daten laden
	// fmt.Println(cfg.Users.UserFile)
	if user, found := userExists(userName); found {
		pwd := []byte(strings.TrimSpace(password))
		err := bcrypt.CompareHashAndPassword([]byte(user.Password), pwd)
		if err != nil {
			// der User hat einen gültgen Username und ein gültiges Passwort angegeben
			return User{}, false
		} else {
			return user, true
		}
	}
	return User{}, false
}

func userExists(userName string) (User, bool) {
	file, err := os.Open(getHome(cfg.Users.UserFile))
	defer file.Close()
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(file)
	users := Users{}
	err = decoder.Decode(&users)
	if err != nil {
		panic(err)
	}

	userName = strings.TrimSpace(userName)
	user := User{}
	found := false
	// fmt.Println("Looking for: " + userName)
	for _, u := range users.Users {
		// fmt.Println("User name: " + u.UserName)
		if u.UserName == userName {
			found = true
			user = u
			// fmt.Println("found user")
			break
		}
	}
	if found {
		return user, true
	} else {
		return User{}, false
	}
}

// Speichert die IP-Adresse zu einem Benutzer in der entsprechenden Textdatei
func saveAddress(userName, ipAddress string) {
	file, _ := os.OpenFile(getHome(cfg.IPTables.AddressDir)+string(os.PathSeparator)+userName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	defer file.Close()
	file.WriteString(ipAddress)
}

var addresses []string

// aktualisiert die iptables-Regeln
func updateIpTables() {
	addresses = nil
	filepath.Walk(getHome(cfg.IPTables.AddressDir), visitAddress)

	var arguments []string
	var cmd *exec.Cmd

	if cfg.IPTables.RunWithSudo {
		arguments = append(arguments, getHome(cfg.IPTables.Runscript))
		arguments = append(arguments, addresses...)
		cmd = exec.Command("/usr/bin/sudo", arguments...)
	} else {
		cmd = exec.Command(getHome(cfg.IPTables.Runscript), addresses...)
	}

	stdout, err := cmd.Output()

	if err != nil {
		println(err.Error())
		return
	}

	print(string(stdout))
}

func visitAddress(path string, f os.FileInfo, err error) error {
	// fmt.Println(path)
	file, _ := os.Open(path)
	defer file.Close()
	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		addresses = append(addresses, scanner.Text())
	}
	return nil
}

func createUser(w http.ResponseWriter, r *http.Request) {
	// CORS-Support
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var json_response []byte
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}
	if newUserName := strings.TrimSpace(r.Form.Get("user")); len(newUserName) > 0 {
		if newPassword := strings.TrimSpace(r.Form.Get("password")); len(newPassword) > 0 {
			if _, exists := userExists(newUserName); exists {
				json_response, _ = json.Marshal(Response{-41, "Ein Benutzer mit diesem Namen existiert bereits", ""})
			} else {
				match, _ := regexp.MatchString("[A-Za-z0-9_]", newUserName)
				if match {
					saveUser(newUserName, newPassword)
					json_response, _ = json.Marshal(Response{0, "Der Benutzer mit dem Namen " + newUserName + " wurde erfolgreich angelegt.", newUserName})
				} else {
					json_response, _ = json.Marshal(Response{-42, "Der Benutzername darf nur aus Buchstaben (a-z), Ziffern und Unterstrichen bestehen.", ""})
				}
			}
			fmt.Fprintf(w, string(json_response))
			return
		}
		json_response, _ = json.Marshal(Response{-12, "Kein Passwort angegeben", ""})
		fmt.Fprintf(w, string(json_response))
		return
	}
	json_response, _ = json.Marshal(Response{-11, "Kein Benutzername angegeben", ""})
	fmt.Fprintf(w, string(json_response))
}

func saveUser(userName, password string) {
	file, err := os.OpenFile(getHome(cfg.Users.UserFile), os.O_RDONLY, 0600)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(file)
	users := Users{}
	err = decoder.Decode(&users)
	if err != nil {
		panic(err)
	}
	file.Close()

	pwd := []byte(password)

	passwordHash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	user := User{userName, string(passwordHash), 0}
	users.Users = append(users.Users, user)

	// wegen der Sicherheit erstellen wir erst einmal eine leere Datei
	tmpFile, err := ioutil.TempFile(os.TempDir(), "ip_setter")
	if err != nil {
		panic(err)
	}
	encoder := json.NewEncoder(tmpFile)
	err = encoder.Encode(&users)
	if err != nil {
		panic(err)
	}
	name := tmpFile.Name()
	tmpFile.Close()

	copy(name, getHome(cfg.Users.UserFile))
	os.Remove(name)
}

// Helfer-FUnktion zum kopieren
func copy(src string, dst string) {
	// Read all content of src to data
	data, err := ioutil.ReadFile(src)
	if err != nil {
		panic(err)
	}
	// Write data to dst
	err = ioutil.WriteFile(dst, data, 0600)
	if err != nil {
		panic(err)
	}
}

func manage(w http.ResponseWriter, r *http.Request) {
	// CORS-Support
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	var json_response []byte
	if _, priv := getUser(w, r); priv >= 2 {
		if strings.TrimSpace(r.Form.Get("action")) == "setPrivileges" {
			if user, exists := userExists(strings.TrimSpace(r.Form.Get("changeUser"))); exists {
				if newPriv := strings.TrimSpace(r.Form.Get("privileges")); len(newPriv) > 0 {
					if newPrivValue, err := strconv.ParseInt(newPriv, 10, 0); err == nil && newPrivValue >= 0 {
						user.Privileges = int(newPrivValue)
						updateUser(user)
						json_response, _ = json.Marshal(Response{0, "Berechtigungen erfolgreich gesetzt", user.UserName})
						fmt.Fprintf(w, string(json_response))
						return
					}
					json_response, _ = json.Marshal(Response{-61, "Die Berechtigung muss eine positive Zahl sein", ""})
					fmt.Fprintf(w, string(json_response))
					return
				}
				json_response, _ = json.Marshal(Response{-13, "Keine Berechtigung angegeben", ""})
				fmt.Fprintf(w, string(json_response))
				return
			}
			json_response, _ = json.Marshal(Response{-43, "Der zu ändernde Benutzer existiert nicht", ""})
			fmt.Fprintf(w, string(json_response))
			return
		}
		json_response, _ = json.Marshal(Response{-51, "Geben Sie eine gültige Funktion an", ""})
		fmt.Fprintf(w, string(json_response))
		return
	}
	json_response, _ = json.Marshal(Response{-30, "Nicht genügend Rechte", ""})
	fmt.Fprintf(w, string(json_response))
	return
}

func updateUser(user User) {
	file, err := os.OpenFile(getHome(cfg.Users.UserFile), os.O_RDONLY, 0600)
	if err != nil {
		panic(err)
	}
	decoder := json.NewDecoder(file)
	users := Users{}
	err = decoder.Decode(&users)
	if err != nil {
		panic(err)
	}
	file.Close()

	var newUsers []User

	for _, u := range users.Users {
		if u.UserName == user.UserName {
			newUsers = append(newUsers, user)
		} else {
			newUsers = append(newUsers, u)
		}
	}

	users.Users = newUsers

	// wegen der Sicherheit erstellen wir erst einmal eine leere Datei
	tmpFile, err := ioutil.TempFile(os.TempDir(), "ip_setter")
	if err != nil {
		panic(err)
	}
	encoder := json.NewEncoder(tmpFile)
	err = encoder.Encode(&users)
	if err != nil {
		panic(err)
	}
	name := tmpFile.Name()
	tmpFile.Close()

	copy(name, getHome(cfg.Users.UserFile))
	os.Remove(name)
}

// Logt den Nutzer ein
// Wenn der Nutzer nicht eingelogt wurde, gibt sie -1 zurück,
// ansonsten die Rechte des Nutzers
func getUser(w http.ResponseWriter, r *http.Request) (User, int) {
	err := r.ParseForm()
	if err != nil {
		panic(err)
	}

	var json_response []byte
	// Wir checken dann mal den gegebenen Username und das Passwort test
	if userName := r.Form.Get("user"); len(userName) > 0 {
		if password := r.Form.Get("password"); len(password) > 0 {
			if user, ok := authenticate(userName, password); ok {
				return user, user.Privileges
			}
			json_response, _ = json.Marshal(Response{-21, "Falscher Benutzername oder Passwort", ""})
			fmt.Fprintf(w, string(json_response))
			return User{}, -1
		}
		json_response, _ = json.Marshal(Response{-12, "Kein Passwort angegeben", ""})
		fmt.Fprintf(w, string(json_response))
		return User{}, -1
	}
	json_response, _ = json.Marshal(Response{-11, "Kein Benutzername angegeben", ""})
	fmt.Fprintf(w, string(json_response))
	return User{}, -1
}

// Helfer-Funktion, die das Heimatverzeichnis eines Users expandiert
func getHome(path string) string {
	usr, _ := user.Current()
	home := usr.HomeDir

	if path[:2] == "~/" {
		path = strings.Replace(path, "~/", home+"/", 1)
	}
	return path
}

// main liest die Konfiguration ein und startet dann den Webserver
func main() {
	var configFilePath string
	flag.StringVar(&configFilePath, "config-file", "auth-ip-config.gcfg", "Gibt den Pfad zur Konfigurationsdatei an")
	flag.Parse()

	err := gcfg.ReadFileInto(&cfg, configFilePath)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/", getIP)
	http.HandleFunc("/create", createUser)
	http.HandleFunc("/manage", manage)

	err = http.ListenAndServe("127.0.0.1:2342", nil)
	if err != nil {
		panic(err)
	}
}
