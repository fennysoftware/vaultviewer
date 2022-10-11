package backend

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/hashicorp/vault/api"
	vault "github.com/hashicorp/vault/api"
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

type VaultInstance struct {
	Address   string        `yaml:"url"`
	Namespace string        `yaml:"namespace"`
	Auth      *VaultAuth    `yaml:"auth"`
	Client    *vault.Client `yaml:"-"`
	Acl       ACL           `yaml:"-"`
}

func ConnectVaultInstance(Address string, Namespace string) (VaultInstance, error) {
	config := vault.DefaultConfig()
	config.Address = Address
	client, err := vault.NewClient(config)
	ns := client.Namespace()

	if len(Namespace) > 0 {
		client.SetNamespace(Namespace)
		ns = Namespace
	}
	vi := VaultInstance{}
	vi.Address = Address
	if ns == "" {
		vi.Namespace = "Default"
	} else {
		vi.Namespace = ns
	}

	if err != nil {
		return vi, err
	}

	vi.Client = client
	return vi, nil
}

func (vi VaultInstance) Login() (VaultInstance, error) {
	if vi.Auth == nil {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Enter Username: ")
		text, err := reader.ReadString('\n')
		if err != nil {
			return vi, err
		}
		username := strings.Replace(text, "\n", "", -1)

		fmt.Printf("Enter Password for %s: ", username)
		text, err = reader.ReadString('\n')
		if err != nil {
			return vi, err
		}
		pwd := strings.Replace(text, "\n", "", -1)

		login, err := vi.loginUsernamePassword(username, pwd)
		if err != nil {
			return vi, err
		}
		vi.Client.SetToken(login.Auth.ClientToken)
		return vi, nil
	} else {
		// token first
		// it's easy
		if len(vi.Auth.Token) > 0 {
			vi.Client.SetToken(vi.Auth.Token)
			return vi, nil
		} else {
			if len(vi.Auth.JWT) > 0 {
				login, err := vi.loginJWT(vi.Auth.JWT)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}

			if vi.Auth.LDAP != nil {
				login, err := vi.loginLDAP(vi.Auth.LDAP)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}
			if len(vi.Auth.Username) > 0 {
				pwd := vi.Auth.Password
				if len(pwd) == 0 {
					reader := bufio.NewReader(os.Stdin)
					fmt.Printf("Enter Password for %s: ", vi.Auth.Username)
					text, err := reader.ReadString('\n')
					if err != nil {
						return vi, err
					}
					pwd = strings.Replace(text, "\n", "", -1)
				}
				login, err := vi.loginUsernamePassword(vi.Auth.Username, pwd)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}
			return vi, nil
		}
	}
	return vi, errors.New("failed to login")
}

func (vi VaultInstance) loginLDAP(a *LDAPAuth) (*api.Secret, error) {

	loginData := make(map[string]interface{})

	if a.PasswordFile != "" {
		passwordValue, err := readPasswordFromFile(a.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("error reading password: %w", err)
		}
		loginData["password"] = passwordValue
	} else if a.PasswordEnv != "" {
		passwordValue := os.Getenv(a.PasswordEnv)
		if passwordValue == "" {
			return nil, fmt.Errorf("password was specified with an environment variable with an empty value")
		}
		loginData["password"] = passwordValue
	} else {
		pwd := a.Password
		if len(pwd) == 0 {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Enter Password for %s: ", a.Username)
			text, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			pwd = strings.Replace(text, "\n", "", -1)

		}
		loginData["password"] = pwd
	}

	mp := a.MountPath
	if len(mp) == 0 {
		mp = "ldap"
	}

	path := fmt.Sprintf("auth/%s/login/%s", mp, a.Username)
	ctx := context.Background()

	login, err := vi.Client.Logical().WriteWithContext(ctx, path, loginData)
	if err != nil {
		return nil, fmt.Errorf("unable to log in with LDAP auth: %w", err)
	}
	return login, nil
}

func readPasswordFromFile(path string) (string, error) {
	passwordFile, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("unable to open file containing password: %w", err)
	}
	defer passwordFile.Close()

	limitedReader := io.LimitReader(passwordFile, 1000)
	passwordBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return "", fmt.Errorf("unable to read password: %w", err)
	}

	passwordValue := strings.TrimSuffix(string(passwordBytes), "\n")

	return passwordValue, nil
}

func (vi VaultInstance) loginUsernamePassword(U string, P string) (*api.Secret, error) {
	// to pass the password
	options := map[string]interface{}{
		"password": P,
	}

	// the login path
	path := fmt.Sprintf("auth/userpass/login/%s", U)

	// PUT call to get a token
	login, err := vi.Client.Logical().Write(path, options)
	if err != nil {
		return nil, err
	}
	return login, nil
}

func (vi VaultInstance) loginJWT(JWT string) (*api.Secret, error) {
	// to pass the password
	options := map[string]interface{}{
		"jwt": JWT,
	}
	// PUT call to get a token
	login, err := vi.Client.Logical().Write("auth/jwt/login", options)
	if err != nil {
		return nil, err
	}
	return login, nil
}

func (vi VaultInstance) GetACL() (VaultInstance, error) {
	// let's use background context
	ctx := context.Background()

	//sys/internal/ui/resultant-acl
	resultant_acl, err := vi.Client.Logical().ReadWithContext(ctx, "sys/internal/ui/resultant-acl/")
	if err != nil {
		log.Printf("unable to get policies: %v", err)
		return vi, err
	} else {
		if resultant_acl != nil {

			log.Printf("%v\n", resultant_acl.Data)
			for k, v := range resultant_acl.Data {
				switch k {
				case "glob_paths":
					ips := v.(map[string]interface{})
					ep := toPathPermissions(ips)
					if ep != nil {
						vi.Acl.PrefixRules = ep
					}
				case "exact_paths":
					ips := v.(map[string]interface{})
					ep := toPathPermissions(ips)
					if ep != nil {
						vi.Acl.ExactRules = ep
					}
				case "root":
					ips := v.(bool)
					vi.Acl.Root = ips
				default:
					log.Printf("\n%s:%v\n", k, v)
				}
			}
			log.Printf("\nACL:\n\n%v\n", vi.Acl)
		}
	}
	return vi, nil
}
