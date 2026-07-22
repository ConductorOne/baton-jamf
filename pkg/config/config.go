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

	// CreateAccountResourceTypeField picks which of the two Jamf account types
	// C1 is allowed to create/delete accounts for. Jamf has two distinct
	// account types (directory "user" resources and Jamf Pro console admin
	// "userAccount" resources) and the platform only supports configuring one
	// creatable type per connector instance. Both types still sync for
	// visibility regardless of this setting, and deletion isn't limited by
	// it — only creation is gated.
	CreateAccountResourceTypeField = field.SelectField(
		"create-account-resource-type",
		[]string{"user", "userAccount"},
		field.WithDisplayName("Account Provisioning Target"),
		field.WithDescription(
			"Which Jamf account type C1 should create when provisioning accounts. "+
				"'user' (default) creates directory users; 'userAccount' creates Jamf Pro console admin accounts. "+
				"Only one type can be created at a time per connector instance.",
		),
		field.WithDefaultValue("user"),
	).ExportAs(field.ExportTargetGUI)

	// ConfigurationFields defines the external configuration required for the
	// connector to run.
	ConfigurationFields = []field.SchemaField{
		UsernameField,
		PasswordField,
		InstanceUrlField,
		CreateAccountResourceTypeField,
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
