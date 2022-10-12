package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"
)

type LDAPAuth struct {
	MountPath    string `yaml:"mountPath"`
	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"passwordFile"`
	PasswordEnv  string `yaml:"passwordEnv"`
}

type VaultAuth struct {
	LDAP     *LDAPAuth `yaml:"ldap"`
	Username string    `yaml:"user"`
	Password string    `yaml:"password"`
	Token    string    `yaml:"token"`
	JWT      string    `yaml:"jwt"`
}

type VaultConfig struct {
	Name      string     `yaml:"name"`
	Address   string     `yaml:"url"`
	Namespace string     `yaml:"namespace"`
	Auth      *VaultAuth `yaml:"auth"`
}

type VaultInstanceConfig struct {
	Instances []*VaultConfig `yaml:"instances"`
}

func LoadConfig(path string) (VaultInstanceConfig, error) {
	// instance configuration
	vic := VaultInstanceConfig{}

	yamlfile, err := ioutil.ReadFile(path)
	if err != nil {
		return vic, err
	}
	err = yaml.Unmarshal(yamlfile, &vic)
	if err != nil {
		return vic, err
	}
	return vic, nil
}
