package main

import (
	"context"
	"fmt"

	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/spf13/cobra"
)

// config defines the external configuration required for the connector to run.
type config struct {
	cli.BaseConfig `mapstructure:",squash"` // Puts the base config options in the same place as the connector options

	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"password"`
	InstanceURL string `mapstructure:"instance-url"`
}

// validateConfig is run after the configuration is loaded, and should return an error if it isn't valid.
func validateConfig(ctx context.Context, cfg *config) error {
	if cfg.Username == "" {
		return fmt.Errorf("username is missing")
	}
	if cfg.Password == "" {
		return fmt.Errorf("password is missing")
	}
	if cfg.InstanceURL == "" {
		return fmt.Errorf("instance URL is missing")
	}

	return nil
}

// cmdFlags sets the cmdFlags required for the connector.
func cmdFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().String("username", "", "Username for your Jamf Pro instance. ($BATON_USERNAME)")
	cmd.PersistentFlags().String("password", "", "Password for your Jamf Pro instance. ($BATON_PASSWORD)")
	cmd.PersistentFlags().String("instance-url", "", "URL of your Jamf Pro instance. ($BATON_INSTANCE_URL)")
}
