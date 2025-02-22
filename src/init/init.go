package init

import (
	"fmt"
	"inventory/src/acl"
	"inventory/src/login"
	"inventory/src/types"
	"time"

	"inventory/src/db"

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
	
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	err = redis.CreateJSONDocument(creds, "auth", ".", false)
	if err != nil {
		return err
	}
	err = redis.CreateJSONDocument(u, "user", ".", false)
	if err != nil {
		return err
	}
	fmt.Printf("System user created:\nUsername: system\nPassword: %s", password)
	return nil
}

func CreateAdminRole() error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}
	role := acl.Role{
		Id: uuid.NewString(),
		Name: "admin",
		Policies: acl.Policies{},
		DefaultPermisison: "all",
	}
	err = redis.CreateJSONDocument(role, "role", ".", false)
	if err != nil {
		return err
	}
	logoutPolicy := acl.NewPolicy("admin-logout", "admin", "/logout", "all")
	createPolicyPolicy := acl.NewPolicy("admin-policy-create", "admin", "/settings/policy/create", "all")
	policies := acl.Policies{}
	policies = append(policies, *logoutPolicy)
	policies = append(policies, *createPolicyPolicy)
	err = redis.CreateJSONDocument(logoutPolicy, "policy", ".", false)
	return err
}
