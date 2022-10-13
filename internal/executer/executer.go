package executer

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/fennysoftware/vaultviewer/internal/backend"
)

func Runner(vi *backend.VaultInstance) {

	shell := os.Getenv("SHELL")
	if shell != "" {
		shell = "zsh"
	}
	opencommand := fmt.Sprintf("open --env VAULT_ADDR=%s --env VAULT_TOKEN=%s -na Terminal ~/", vi.Client.Address(), vi.Client.Token())
	if vi.Client.Namespace() != "" {
		opencommand = fmt.Sprintf("open --env VAULT_ADDR=%s --env VAULT_TOKEN=%s --env VAULT_NAMESPACE=%s -na Terminal ~/", vi.Client.Address(), vi.Client.Token(), vi.Client.Namespace())
	}
	cmd := exec.Command(shell, "-c", opencommand)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	err := cmd.Run()
	if err != nil {
		panic(fmt.Errorf("%s - %v", shell, err))
	}

}
