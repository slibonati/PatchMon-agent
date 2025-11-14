package commands

import (
	"context"
	"fmt"
	"os"

	"github.com/apenella/go-ansible/v2/pkg/execute"
	"github.com/apenella/go-ansible/v2/pkg/playbook"
	"github.com/spf13/cobra"
)

// ansiblePlaybookCmd represents the ansible-playbook command
var ansiblePlaybookCmd = &cobra.Command{
	Use:   "ansible-playbook [playbook-path]",
	Short: "Execute an Ansible playbook",
	Long: `Execute an Ansible playbook using the go-ansible library.

This command allows you to run Ansible playbooks from the PatchMon agent.
The playbook path should be an absolute or relative path to a valid Ansible playbook YAML file.

Example:
  patchmon-agent ansible-playbook /etc/patchmon/profiles/myplaybook.yml
  patchmon-agent --ansible-playbook /etc/patchmon/profiles/myplaybook.yml`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		playbookPath := args[0]

		// Check if playbook file exists
		if _, err := os.Stat(playbookPath); os.IsNotExist(err) {
			return fmt.Errorf("playbook file not found: %s", playbookPath)
		}

		return runAnsiblePlaybook(playbookPath)
	},
}

// runAnsiblePlaybook executes an Ansible playbook
func runAnsiblePlaybook(playbookPath string) error {
	logger.WithField("playbook", playbookPath).Info("Executing Ansible playbook")

	ctx := context.Background()

	// Define the playbook options
	playbookOptions := &playbook.AnsiblePlaybookOptions{
		Inventory: "localhost,", // Default to localhost, can be made configurable
	}

	// Create the Ansible playbook command
	playbookCmd := &playbook.AnsiblePlaybookCmd{
		Playbooks:       []string{playbookPath},
		PlaybookOptions: playbookOptions,
	}

	// Create executor and execute the playbook
	exec := execute.NewDefaultExecute(
		execute.WithCmd(playbookCmd),
		execute.WithErrorEnrich(playbook.NewAnsiblePlaybookErrorEnrich()),
	)

	// Execute the playbook
	err := exec.Execute(ctx)
	if err != nil {
		logger.WithError(err).Error("Failed to execute Ansible playbook")
		return fmt.Errorf("playbook execution failed: %w", err)
	}

	logger.Info("✅ Ansible playbook executed successfully")
	fmt.Println("✅ Ansible playbook executed successfully")
	return nil
}
