package config

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"

	"github.com/fennysoftware/vaultviewer/internal/backend"
)

type VaultInstanceConfig struct {
	Instances []*backend.VaultInstance `yaml:"instances"`
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
