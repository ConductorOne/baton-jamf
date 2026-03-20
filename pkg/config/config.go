package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	UsernameField = field.StringField(
		"username",
		field.WithDisplayName("Username"),
		field.WithDescription("Username for your Jamf Pro instance"),
		field.WithRequired(true),
	)
	PasswordField = field.StringField(
		"password",
		field.WithDisplayName("Password"),
		field.WithDescription("Password for your Jamf Pro instance"),
		field.WithIsSecret(true),
		field.WithRequired(true),
	)
	InstanceUrlField = field.StringField(
		"instance-url",
		field.WithDisplayName("Instance URL"),
		field.WithDescription("URL of your Jamf Pro instance"),
		field.WithRequired(true),
	)

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		UsernameField,
		PasswordField,
		InstanceUrlField,
	}

	// FieldRelationships defines relationships between the fields listed in
	// ConfigurationFields that can be automatically validated.
	FieldRelationships = []field.SchemaFieldRelationship{}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	ConfigurationFields,
	field.WithConstraints(FieldRelationships...),
	field.WithConnectorDisplayName("Jamf"),
	field.WithHelpUrl("/docs/baton/jamf"),
	field.WithIconUrl("/static/app-icons/jamf.svg"),
)
