package backend

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/fennysoftware/vaultviewer/internal/config"
	"github.com/hashicorp/vault/api"
	vault "github.com/hashicorp/vault/api"
)

type VaultInstance struct {
	DisplayName string        `yaml:"-"`
	Client      *vault.Client `yaml:"-"`
	Acl         ACL           `yaml:"-"`
}

func ConnectVaultInstance(vconfig *config.VaultConfig) (VaultInstance, error) {
	config := vault.DefaultConfig()
	config.Address = vconfig.Address
	client, err := vault.NewClient(config)
	if len(vconfig.Namespace) > 0 {
		client.SetNamespace(vconfig.Namespace)
	}
	vi := VaultInstance{}

	if len(vconfig.Name) == 0 {
		vi.DisplayName = client.Address() + " - " + client.Namespace()
	} else {
		vi.DisplayName = vconfig.Name
	}

	if err != nil {
		return vi, err
	}

	vi.Client = client
	return vi, nil
}

func (vi VaultInstance) Login(vconfig *config.VaultConfig) (VaultInstance, error) {
	if vconfig.Auth == nil {
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
		if len(vconfig.Auth.Token) > 0 {
			vi.Client.SetToken(vconfig.Auth.Token)
			return vi, nil
		} else {
			if len(vconfig.Auth.JWT) > 0 {
				login, err := vi.loginJWT(vconfig.Auth.JWT)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}

			if vconfig.Auth.LDAP != nil {
				login, err := vi.loginLDAP(vconfig.Auth.LDAP)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}
			if len(vconfig.Auth.Username) > 0 {
				pwd := vconfig.Auth.Password
				if len(pwd) == 0 {
					reader := bufio.NewReader(os.Stdin)
					fmt.Printf("Enter Password for %s: ", vconfig.Auth.Username)
					text, err := reader.ReadString('\n')
					if err != nil {
						return vi, err
					}
					pwd = strings.Replace(text, "\n", "", -1)
				}
				login, err := vi.loginUsernamePassword(vconfig.Auth.Username, pwd)
				if err != nil {
					return vi, err
				}
				vi.Client.SetToken(login.Auth.ClientToken)
			}
			return vi, nil
		}
	}
}

func (vi VaultInstance) loginLDAP(a *config.LDAPAuth) (*api.Secret, error) {

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

	// make sure it's cleared out
	vi.Acl = ACL{}

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

func BuildAndConnect(vconfig *config.VaultConfig) (VaultInstance, error) {
	vi, err := ConnectVaultInstance(vconfig)
	if err != nil {
		log.Printf("unable to initialize Vault client: %v", err)
		return vi, err
	} else {

		update, err := vi.Login(vconfig)
		if err != nil {
			log.Printf("unable to login: %v", err)
			return vi, err
		}
		vi = update
		update, err = vi.GetACL()
		if err != nil {
			log.Printf("unable to get ACL: %v", err)
			return vi, err
		}
		vi = update
	}

	return vi, nil
}
