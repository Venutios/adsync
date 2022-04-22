package main

type Configuration struct {
	ActiveDirectory struct {
		Host     string
		Domain   string
		Username string
		Password string
		UserDN   string
		GroupDN  string
		Group    string
	}
	Logging struct {
		Enabled  bool
		Location string
	}
}
