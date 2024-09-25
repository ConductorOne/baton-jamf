package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	UsernameField = field.StringField(
		"username",
		field.WithDescription("Username for your Jamf Pro instance"),
		field.WithRequired(true),
	)
	PasswordField = field.StringField(
		"password",
		field.WithDescription("Password for your Jamf Pro instance"),
		field.WithRequired(true),
	)
	InstanceUrlField = field.StringField(
		"instance-url",
		field.WithDescription("URL of your Jamf Pro instance"),
		field.WithRequired(true),
	)
	Configuration = field.NewConfiguration([]field.SchemaField{
		UsernameField,
		PasswordField,
		InstanceUrlField,
	})
)
