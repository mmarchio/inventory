package init

import (
	"context"
	"fmt"
	"inventory/src/acl"
	"inventory/src/login"
	"inventory/src/types"
	"time"

	"github.com/google/uuid"
)

func CreateSystemUser(ctx context.Context) error {
	now := time.Now()
	u := types.User{
		Roles: []string{"system"},
		Firstname: "system",
		Middlenames: []string{"system"},
		Lastname: "system",
		DOB: &now,
		Username: "system",
	}
	a := types.NewAttributes(ctx, nil)
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
	attributesPtr, err := creds.Attributes.New(ctx)
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
	err = creds.PGCreate(ctx)
	if err != nil {
		return err
	}
	u.Attributes.ParentId = u.Attributes.Id
	u.Attributes.RootId = u.Attributes.Id
	u.Attributes.Owner = u.Attributes.Id
	u.Attributes.ContentType = "user"
	err = u.PGCreate(ctx)
	if err != nil {
		return nil
	}
	fmt.Printf("System user created:\nUsername: system\nPassword: %s", password)
	return nil
}

func CreateAdminRole(ctx context.Context) error {
	role := acl.Role{}
	attributesPtr, err := role.Attributes.New(ctx)
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
	err = role.PGCreate(ctx)
	if err != nil {
		return err
	}
	logoutPolicy := acl.NewPolicy(ctx, "admin-logout", "admin", "/logout", "all")
	createPolicyPolicy := acl.NewPolicy(ctx, "admin-policy-create", "admin", "/settings/policy/create", "all")
	policies := acl.Policies{}
	policies = append(policies, *logoutPolicy)
	policies = append(policies, *createPolicyPolicy)
	existingPolicies, err := policies.SelectIn(ctx)
	if err != nil {
		return err
	}
	newPolicies := acl.Policies{}
	for _, policy := range policies {
		if existingPolicies.In(ctx, policy.Attributes.Id) {
			continue
		}
		newPolicies = append(newPolicies, policy)
	}
	err = newPolicies.CreateMany(ctx)
	if err != nil {
		return err
	}
	return nil
}
