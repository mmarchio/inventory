package init

import (
	"fmt"
	"inventory/src/acl"
	"inventory/src/login"
	"inventory/src/types"
	"time"

	"github.com/google/uuid"
)

func CreateSystemUser() error {
	now := time.Now()
	u := types.User{
		Roles: []string{"system"},
		Firstname: "system",
		Middlenames: []string{"system"},
		Lastname: "system",
		DOB: &now,
		Username: "system",
	}
	a := types.NewAttributes(nil)
	if a != nil {
		u.Attributes = *a
	}
	password := uuid.NewString()
	hash, err := login.HashPassword(password)
	if err != nil {
		return err
	}
	creds := login.Credentials{
		Username: u.Username,
		Password: hash,
	}
	attributesPtr, err := creds.Attributes.New()
	if err != nil {
		return err
	}
	if attributesPtr == nil {
		return fmt.Errorf("attributes is nil")
	}
	creds.Attributes = *attributesPtr

	creds.Attributes.ParentId = creds.Attributes.Id
	creds.Attributes.RootId = creds.Attributes.Id
	creds.Attributes.Owner = creds.Attributes.Id
	creds.Attributes.ContentType = "credentials"
	err = creds.PGCreate()
	if err != nil {
		return err
	}
	u.Attributes.ParentId = u.Attributes.Id
	u.Attributes.RootId = u.Attributes.Id
	u.Attributes.Owner = u.Attributes.Id
	u.Attributes.ContentType = "user"
	err = u.PGCreate()
	if err != nil {
		return nil
	}
	fmt.Printf("System user created:\nUsername: system\nPassword: %s", password)
	return nil
}

func CreateAdminRole() error {
	role := acl.Role{}
	attributesPtr, err := role.Attributes.New()
	if err != nil {
		return err
	}
	if attributesPtr == nil {
		return fmt.Errorf("attributes is nil")
	}
	role = acl.Role{
		Attributes: *attributesPtr,
		Name: "admin",
		Policies: acl.Policies{},
		DefaultPermisison: "all",
	}
	err = role.PGCreate()
	if err != nil {
		return err
	}
	logoutPolicy := acl.NewPolicy("admin-logout", "admin", "/logout", "all")
	createPolicyPolicy := acl.NewPolicy("admin-policy-create", "admin", "/settings/policy/create", "all")
	policies := acl.Policies{}
	policies = append(policies, *logoutPolicy)
	policies = append(policies, *createPolicyPolicy)
	for _, p := range policies {
		err = p.PGCreate()
		if err != nil {
			return err
		}
	}
	return logoutPolicy.PGCreate()
}
