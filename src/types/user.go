package types

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/util"
	"time"

	"github.com/jackc/pgx/v5"
)

type User struct {
	Attributes
	Roles       []string   `json:"roles"`
	Firstname   string     `json:"name"`
	Middlenames []string   `json:"middlenames"`
	Lastname    string     `json:"lastname"`
	Maidenname  string     `json:"maidenname"`
	Nameprefix  string     `json:"nameprefix"`
	Namesuffix  string     `json:"namesuffix"`
	DOB         *time.Time `json:"dob"`
	Username    string     `json:"username"`
	Password    string     `json:"password"`
	Token       string
}

func (c User) New(ctx context.Context) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:New")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	user := c
	attributesPtr, erp := c.Attributes.New(ctx)
	if erp != nil {
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if attributesPtr == nil {
		err := fmt.Errorf("attributes is nil")
		fidx := "types:Attributes:New"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	user.Attributes = *attributesPtr
	user.Attributes.ContentType = "user"
	return &user, nil
}

func (c User) ToContent(ctx context.Context) (*Content, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:ToContent")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "ToContent", "User")
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content.Content = jbytes
	return &content, nil
}

func (c User) Merge(ctx context.Context, old, new User) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:Merge")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "Merge", "User")
	attributesPtr, erp := c.Attributes.Merge(ctx, old.Attributes, new.Attributes)
	if erp != nil {
		fidx := "types:Attributes:Merge"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if attributesPtr != nil {
		new.Attributes = *attributesPtr
	}
	if len(new.Roles) == 0 {
		new.Roles = old.Roles
	}
	if new.Firstname == "" {
		new.Firstname = old.Firstname
	}
	if len(new.Middlenames) == 0 {
		new.Middlenames = old.Middlenames
	}
	if new.Lastname == "" {
		new.Lastname = old.Lastname
	}
	if new.Maidenname == "" {
		new.Maidenname = old.Maidenname
	}
	if new.Nameprefix == "" {
		new.Nameprefix = old.Nameprefix
	}
	if new.Namesuffix == "" {
		new.Namesuffix = old.Namesuffix
	}
	if new.DOB == nil {
		new.DOB = old.DOB
	}
	return &new, nil
}

func (c User) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	data, erp := toMSI(ctx, c)
	if erp != nil {
		fidx := "types:toMSI"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return data, nil
}

type Users []User

func (c Users) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:users:IsDocument")
	}
	return true
}

func (c Users) ToMSI(ctx context.Context) (map[string]interface{}, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:users:ToMSI")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "ToMSI", "Users")
	data, erp := toMSI(ctx, c)
	if erp != nil {
		fidx := "types:toMSI"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return data, nil
}

func NewUser(ctx context.Context) *User {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:NewUser")
	}
	u := User{}
	u.Attributes = *NewAttributes(ctx, nil)
	return &u
}

func (c User) Hydrate(ctx context.Context, msi map[string]interface{}) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:Hydrate")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "Hydrate", "User")
	u := User{}
	if m, ok := msi["attributes"].(map[string]interface{}); ok {
		erp := u.Attributes.MSIHydrate(ctx, m)
		if erp != nil {
			fidx := "types:Attributes:MSIHydrate"
			errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
			return nil, &e
		}
	}
	if v, ok := msi["roles"].(string); ok {
		u.Roles = []string{v}
	}
	if v, ok := msi["firstname"].(string); ok {
		u.Firstname = v
	}
	if v, ok := msi["middlenames"].(string); ok {
		u.Middlenames = []string{v}
	}
	if v, ok := msi["lastname"].(string); ok {
		u.Lastname = v
	}
	if v, ok := msi["maidenname"].(string); ok {
		u.Maidenname = v
	}
	if v, ok := msi["nameprefix"].(string); ok {
		u.Nameprefix = v
	}
	if v, ok := msi["namesuffix"].(string); ok {
		u.Namesuffix = v
	}
	if v, ok := msi["dob"].(string); ok {
		f := "01/02/2006"
		if v != "" {
			dob, err := time.Parse(f, v)
			if err != nil {
				fidx := "time:Parse"
				errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
				return nil, &e
			}
			u.DOB = &dob
		}
	}
	if v, ok := msi["username"].(string); ok {
		u.Username = v
	}
	if v, ok := msi["password"].(string); ok {
		u.Password = v
	}
	return &u, nil
}

func GetUser(ctx context.Context, id string) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:GetUser")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "GetUser", "")
	usersPtr, erp := GetUsers(ctx)
	if erp != nil {
		fidx := "types:GetUsers"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if usersPtr != nil {
		users := *usersPtr
		for _, user := range users {
			if user.Attributes.Id == id {
				return &user, nil
			}
		}
	}
	err := fmt.Errorf("user id: %s not found", id)
	e[idx].Err(ctx, err)
	return nil, &e
}

func (c User) FindBy(ctx context.Context, jstring string) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:FindBy")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	contentPtr, erp := Content{}.FindBy(ctx, jstring)
	if erp != nil {
		fidx := "types:Content:FindBy"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		fidx := "types:Content:FindBy"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content := *contentPtr
	user := User{}
	err := json.Unmarshal(content.Content, &user)
	if err != nil {
		fidx := "json:Unmarshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return &user, nil
}

func (c Users) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:users.go:user:In")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Users) FindAll(ctx context.Context) (*Users, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:users:FindAll")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "FindAll", "Users")
	jstring := "{\"contentType\": \"location\"}"
	contents, erp := Content{}.FindAll(ctx, jstring)
	if erp != nil {
		fidx := "types:Content:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	users := c
	for _, content := range contents {
		user := User{}
		err := json.Unmarshal(content.Content, &user)
		if err != nil {
			fidx := "json:Unmarshal"
			errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
			return nil, &e
		}
		users = append(users, user)
	}
	return &users, nil
}

func GetUsers(ctx context.Context) (*Users, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:GetUsers")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "GetUsers", "")
	u, erp := Users{}.FindAll(ctx)
	if erp != nil {
		fidx := "types:Users:FindAll"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return u, nil
}

func (c User) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:IsDocument")
	}
	return true
}

func (c User) HasRole(ctx context.Context, role string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:HasRole")
	}
	for _, v := range c.Roles {
		if v == role {
			return true
		}
	}
	return false
}

func (c User) PGHydrate(ctx context.Context, content Content) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:PGHydrate")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "PGHydrate", "User")
	user := c
	attributesPtr := c.Attributes.PGHydrate(ctx, content)
	var err error
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		fidx := "types:Attributes:PGHydrate"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	user.Attributes = *attributesPtr
	err = json.Unmarshal(content.Content, &user)
	if err != nil {
		fidx := "json:Marshal"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	return &user, nil
}

func (c User) PGRead(ctx context.Context, id string) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:PGRead")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "PGRead", "User")
	contentPtr, erp := Content{}.Read(ctx, id)
	if erp != nil {
		fidx := "types:Content:Read"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	if contentPtr == nil {
		err := fmt.Errorf("content is nil")
		fidx := "types:Content:Read"
		errors.CreateErrorEntry(ctx, idx, fidx, nil, err, &e)
		return nil, &e
	}
	content := *contentPtr
	userPtr, erp := c.PGHydrate(ctx, content)
	if erp != nil {
		fidx := "types:User:PGHydrate"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return userPtr, nil
}

func (c User) PGCreate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:PGCreate")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "PGCreate", "User")
	erp := Content{}.Create(ctx, c)
	if erp != nil {
		fidx := "type:Content:Create"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c User) PGUpdate(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:PGUpdate")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	columns := c.Columns(ctx)
	values := c.Values(ctx)
	sets := []string{}
	if len(columns) == len(values) {
		for i := range columns {
			sets = append(sets, fmt.Sprintf("%s = ?", columns[i]))
		}
	}
	content, erp := c.ToContent(ctx)
	if erp != nil {
		fidx := "types:User:ToContent"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	erp = content.Update(ctx, c)
	if erp != nil {
		fidx := "types:Content:Update"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c User) PGDelete(ctx context.Context) *map[string]errors.Error {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:PGDelete")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	erp := Content{}.Delete(ctx, c.Attributes.Id)
	if erp != nil {
		fidx := "types:Content:Delete"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return &e
	}
	return nil
}

func (c User) ScanRow(rows pgx.Rows) error {
	ctx := context.Background()
	defer rows.Close()
	content := Content{}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	err := rows.Scan(&content)
	if err != nil {
		e[idx].Err(ctx, err)
		return err
	}

	if content.ContentType == "user" {
		attributesPtr := c.Attributes.PGHydrate(ctx, content)
		if attributesPtr == nil {
			err = fmt.Errorf("attributes is nil")
			e[idx].Err(ctx, err)
			return err
		}

		msi := make(map[string]interface{})
		err = json.Unmarshal(content.Content, &msi)
		if err != nil {
			e[idx].Err(ctx, err)
			return err
		}
		userPtr, erp := c.Hydrate(ctx, msi)
		if erp != nil {
			ers := *erp
			e[idx].Err(ctx, ers["types:User:Hydrate"].Wrapper)
			return err
		}
		if userPtr == nil {
			err = fmt.Errorf("content body (user) is nil")
			e[idx].Err(ctx, err)
			return err
		}
		c = *userPtr
		c.Attributes = *attributesPtr
	}

	return nil
}

func (c User) Columns(ctx context.Context) []string {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:Columns")
	}
	columns := c.Attributes.Columns(ctx)
	return columns
}

func (c User) Values(ctx context.Context) []interface{} {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:Values")
	}
	values := c.Attributes.Values(ctx)
	return values
}

func UserPGRead(ctx context.Context, id string) (*User, *map[string]errors.Error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:user.go:user:UserPGRead")
	}
	e, idx := errors.Error{}.New(ctx, "user.go", "types", "New", "User")
	u := &User{}
	u, erp := u.PGRead(ctx, id)
	if erp != nil {
		fidx := "types:User:PGRead"
		errors.CreateErrorEntry(ctx, idx, fidx, erp, nil, &e)
		return nil, &e
	}
	return u, nil
}
