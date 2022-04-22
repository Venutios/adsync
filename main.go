package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap"
	"github.com/spf13/viper"
)

var (
	config      Configuration
	logFile     *os.File
	errorLogger *log.Logger
	infoLogger  *log.Logger
	adUsers     []string
	groupUsers  []string
)

func main() {
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath(".")

	viper.SetDefault("logging.enabled", false)
	viper.SetDefault("logging.location", ".")
	viper.SetDefault("activedirectory.host", "127.0.0.1")

	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("unable to read config file: %w", err))
	}

	err = viper.Unmarshal(&config)
	if err != nil {
		panic(fmt.Errorf("config file is corrupt: %w", err))
	}

	if config.Logging.Enabled {
		//generate a log file name based on the current date, create the file or append if it already exists
		now := time.Now()
		logfilename := "adsync" + strconv.Itoa(now.Year()) + strconv.Itoa(int(now.Month())) + strconv.Itoa(now.Day()) + ".log"
		logFile, err = os.OpenFile(filepath.Join(config.Logging.Location, logfilename), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
		if err != nil {
			panic(fmt.Errorf("failed to open log file: %w", err))
		}
		errorLogger = log.New(logFile, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
		infoLogger = log.New(logFile, "INFO: ", log.Ldate|log.Ltime)
	}

	writeInfo("Loading the list of users from Active Directory")
	listADUsers()
	writeInfo("Loading the list of users in group")
	listGroupUsers()
	writeInfo("Synchronizing group membership")
	synchronizeGroup()
}

func writeInfo(msg string) {
	if infoLogger != nil {
		infoLogger.Println(msg)
	}
}

func writeError(err error) {
	if errorLogger != nil {
		errorLogger.Panic(err)
	}
	panic(err)
}

//Populate the adUsers slice with a list of usernames
func listADUsers() {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", config.ActiveDirectory.Host))
	if err != nil {
		writeError(fmt.Errorf("unable to connect to AD server: %w", err))
	}
	defer l.Close()

	username := config.ActiveDirectory.Domain + "\\" + config.ActiveDirectory.Username

	if err := l.Bind(username, config.ActiveDirectory.Password); err != nil {
		writeError(fmt.Errorf("unable to bind to ldap: %w", err))
	}

	//Retrieve only the distinguishedName attribute for all user objects in the OU. Don't go into sub OUs
	searhReq := ldap.NewSearchRequest(config.ActiveDirectory.UserDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, "(&(objectClass=user))", []string{"distinguishedName"}, nil)

	result, err := l.Search(searhReq)
	if err != nil {
		writeError(fmt.Errorf("ldap search error: %w", err))
	}

	if len(result.Entries) > 0 {
		for _, x := range result.Entries {
			adUsers = append(adUsers, strings.ToUpper(x.Attributes[0].Values[0]))
		}
	} else {
		writeError(fmt.Errorf("no results returned from ldap search"))
	}

	writeInfo(strconv.Itoa(len(adUsers)) + " records retrieved")
}

//Populate the groupUsers slice with a list of usernames
func listGroupUsers() {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", config.ActiveDirectory.Host))
	if err != nil {
		writeError(fmt.Errorf("unable to connect to AD server: %w", err))
	}
	defer l.Close()

	username := config.ActiveDirectory.Domain + "\\" + config.ActiveDirectory.Username

	if err := l.Bind(username, config.ActiveDirectory.Password); err != nil {
		writeError(fmt.Errorf("unable to bind to ldap: %w", err))
	}

	//Retrieve only the member attribute for the group
	searhReq := ldap.NewSearchRequest(config.ActiveDirectory.GroupDN, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, fmt.Sprintf("(&(objectClass=group)(cn=%s))", config.ActiveDirectory.Group), []string{"member"}, nil)

	result, err := l.Search(searhReq)
	if err != nil {
		writeError(fmt.Errorf("ldap search error: %w", err))
	}

	for _, x := range result.Entries[0].Attributes[0].Values {
		groupUsers = append(groupUsers, strings.ToUpper(x))
	}

	writeInfo(strconv.Itoa(len(groupUsers)) + " users in group")
}

//Look for users that aren't a member of the group
func synchronizeGroup() {
	for _, x := range adUsers {
		found := false
		for _, y := range groupUsers {
			if x == y {
				found = true
				break
			}
		}

		if !found {
			addUserToGroup(x)
		}
	}
}

//Add a user to the group
func addUserToGroup(name string) {
	l, err := ldap.DialURL(fmt.Sprintf("ldap://%s:389", config.ActiveDirectory.Host))
	if err != nil {
		writeError(fmt.Errorf("unable to connect to AD server: %w", err))
	}
	defer l.Close()

	username := config.ActiveDirectory.Domain + "\\" + config.ActiveDirectory.Username

	if err := l.Bind(username, config.ActiveDirectory.Password); err != nil {
		writeError(fmt.Errorf("unable to bind to ldap: %w", err))
	}

	//Add user to group
	modifyReq := ldap.NewModifyRequest(fmt.Sprintf("cn=%s,%s", config.ActiveDirectory.Group, config.ActiveDirectory.GroupDN), []ldap.Control{})
	modifyReq.Add("member", []string{name})

	if err := l.Modify(modifyReq); err != nil {
		writeError(fmt.Errorf("ldap modify error: %w", err))
	}

	writeInfo(fmt.Sprintf("%s added to group", name))
}
