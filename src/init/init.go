package init

import (
	"context"
	"fmt"
	"inventory/src/acl"
	"inventory/src/errors"
	"inventory/src/login"
	"inventory/src/types"
	"inventory/src/util"
	"time"

	"github.com/google/uuid"
)

var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

func CreateSystemUser(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "init:init.go:CreateSystemUser")
	}
	e, idx := errors.Error{}.New(ctx, "init.go", "init", "CreateSystemUser", "")
	now := time.Now()
	u := types.User{
		Roles:       []string{"system"},
		Firstname:   "system",
		Middlenames: []string{"system"},
		Lastname:    "system",
		DOB:         &now,
		Username:    "system",
	}
	a := types.NewAttributes(ctx, nil)
	if a == nil {
		err := fmt.Errorf("attributes is nil")
		fidx := "types:NewAttributes"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return &e
	}
	u.Attributes = *a
	password := uuid.NewString()
	hash, erp := login.HashPassword(password)
	if erp != nil {
		fidx := "login:HashPassword"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	creds := login.Credentials{
		Username: u.Username,
		Password: hash,
	}
	attributesPtr, erp := creds.Attributes.New(ctx)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	if attributesPtr == nil {
		err := fmt.Errorf("attributes is nil")
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return &e
	}
	creds.Attributes = *attributesPtr

	creds.Attributes.ParentId = creds.Attributes.Id
	creds.Attributes.RootId = creds.Attributes.Id
	creds.Attributes.Owner = creds.Attributes.Id
	creds.Attributes.ContentType = "credentials"
	erp = creds.PGCreate(ctx)
	if erp != nil {
		fidx := "login:Credentials:PGCreate"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	u.Attributes.ParentId = u.Attributes.Id
	u.Attributes.RootId = u.Attributes.Id
	u.Attributes.Owner = u.Attributes.Id
	u.Attributes.ContentType = "user"
	erp = u.PGCreate(ctx)
	if erp != nil {
		fidx := "types:User:PGCreate"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	fmt.Printf("System user created:\nUsername: system\nPassword: %s", password)
	return nil
}

func CreateAdminRole(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "init:init.go:CreateAdminRole")
	}
	e, idx := errors.Error{}.New(ctx, "init.go", "init", "CreateAdminRole", "")
	jstring := "{'contentType': 'role', 'name': 'admin'}"
	content := types.Content{}
	adminPtr, erp := content.FindBy(ctx, jstring)
	if erp != nil {
		fidx := "types:Content:FindBy"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}

	role := acl.Role{}
	attributesPtr, erp := role.Attributes.New(ctx)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	if attributesPtr == nil {
		err := fmt.Errorf("attributes is nil")
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return &e
	}
	role = acl.Role{
		Attributes:        *attributesPtr,
		Policies:          acl.Policies{},
		DefaultPermisison: "all",
	}
	role.Attributes.ContentType = "role"
	role.Attributes.Name = "admin"

	if adminPtr == nil {
		erp = role.PGCreate(ctx)
		if erp != nil {
			fidx := "acl:Role:PGCreate"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return &e
		}
	}
	logoutPolicy := acl.NewPolicy(ctx, "admin-logout", "admin", "/logout", "all")
	createPolicyPolicy := acl.NewPolicy(ctx, "admin-policy-create", "admin", "/settings/policy/create", "all")
	policies := acl.Policies{}
	policies = append(policies, *logoutPolicy)
	policies = append(policies, *createPolicyPolicy)
	existingPolicies, erp := policies.SelectIn(ctx)
	if erp != nil {
		fidx := "acl:Policies:SelectIn"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	newPolicies := acl.Policies{}
	for _, policy := range policies {
		if existingPolicies.In(ctx, policy.Attributes.Id) {
			continue
		}
		newPolicies = append(newPolicies, policy)
	}
	erp = newPolicies.CreateMany(ctx)
	if erp != nil {
		fidx := "acl:Policies:CreateMany"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}
