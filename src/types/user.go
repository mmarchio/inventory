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

func (c User) New(ctx context.Context) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:New")
    }
	e := errors.Error{}
	user := c
	attributesPtr, err := c.Attributes.New(ctx, )
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		e.Err(ctx, err)
		return nil, err
	}
	user.Attributes = *attributesPtr
	user.Attributes.ContentType = "user"
	return &user, nil
}

func (c User) ToContent(ctx context.Context) (*Content, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:ToContent")
    }
	e := errors.Error{}
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c User) Merge(ctx context.Context, old, new User) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:Merge")
    }
	e := errors.Error{}
	attributesPtr, err := c.Attributes.Merge(ctx, old.Attributes, new.Attributes)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
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

func (c User) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
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

func (c Users) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:users:ToMSI")
    }
	data, err := toMSI(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, err
}

func NewUser(ctx context.Context) *User {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:NewUser")
    }
	u := User{}
	u.Attributes = *NewAttributes(ctx, nil)
	return &u
}

func (c User) Hydrate(ctx context.Context, msi map[string]interface{}) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:Hydrate")
    }
	u := User{}
	if m, ok := msi["attributes"].(map[string]interface{}); ok {
		u.Attributes.MSIHydrate(ctx, m)
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
				e := errors.Error{}
				e.Err(ctx, err)
				return nil, err
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

func GetUser(ctx context.Context, id string) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:GetUser")
    }
	e := errors.Error{}
	usersPtr, err := GetUsers(ctx)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if usersPtr != nil {
		users := *usersPtr
		for _, user := range users {
			if user.Attributes.Id == id {
				return &user, nil
			}
		}
	}
	err = fmt.Errorf("user id: %s not found", id)
	e.Err(ctx, err)
	return nil, err
}

func (c User) FindBy(ctx context.Context, jstring string) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:FindBy")
    }
	e := errors.Error{}
	contentPtr, err := Content{}.FindBy(ctx, jstring)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return nil, err
	}
	content := *contentPtr
	user := User{}
	err = json.Unmarshal(content.Content, &user)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
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

func (c Users) FindAll(ctx context.Context) (*Users, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:users:FindAll")
    }
	e := errors.Error{}
	jstring := "{\"contentType\": \"location\"}"
	contents, err := Content{}.FindAll(ctx, jstring)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	users := c
	for _, content := range contents {
		user := User{}
		err = json.Unmarshal(content.Content, &user)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		users = append(users, user)
	}
	return &users, nil
}

func GetUsers(ctx context.Context) (*Users, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:GetUsers")
    }
	u, err :=  Users{}.FindAll(ctx)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return u, nil
}

func (i User) MarshalBinary(ctx context.Context) ([]byte, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:MarshalBinary")
    }
	data, err := json.Marshal(i)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return data, nil
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

func (c User) PGHydrate(ctx context.Context, content Content) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:PGHydrate")
    }
	e := errors.Error{}
	user := c
	attributesPtr := c.Attributes.PGHydrate(ctx, content)
	var err error
	if attributesPtr == nil {
		err = fmt.Errorf("attributes is nil")
		e.Err(ctx, err)
		return nil, err
	}
	user.Attributes = *attributesPtr
	err = json.Unmarshal(content.Content, &user)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &user, nil
}

func (c User) PGRead(ctx context.Context, id string) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:PGRead")
    }
	e := errors.Error{}
	contentPtr, err := Content{}.Read(ctx, id)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return nil, err
	}
	content := *contentPtr
	return c.PGHydrate(ctx, content)
}

func (c User) PGCreate(ctx context.Context) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:PGCreate")
    }
	err := Content{}.Create(ctx, c)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c User) PGUpdate(ctx context.Context) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:PGUpdate")
    }
	e := errors.Error{}
	columns := c.Columns(ctx)
	values := c.Values(ctx)
	sets := []string{}
	if len(columns) == len(values) {
		for i := range columns {
			sets = append(sets, fmt.Sprintf("%s = ?", columns[i]))
		}
	}
	content, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	err = content.Update(ctx, c)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c User) PGDelete(ctx context.Context) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:PGDelete")
    }
	err := Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c User) ScanRow(rows pgx.Rows) error {
	ctx := context.Background()
	defer rows.Close()
	content := Content{}
	e := errors.Error{}
	err := rows.Scan(&content)
	if err != nil {
		e.Err(ctx, err)
		return err
	}

	if content.ContentType == "user" {
		attributesPtr := c.Attributes.PGHydrate(ctx, content)
		if attributesPtr == nil {
			err = fmt.Errorf("attributes is nil")
			e.Err(ctx, err)
			return err
		}

		msi := make(map[string]interface{})
		err = json.Unmarshal(content.Content, &msi)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
		userPtr, err := c.Hydrate(ctx, msi)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
		if userPtr == nil {
			err = fmt.Errorf("content body (user) is nil")
			e.Err(ctx, err)
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

func UserPGRead(ctx context.Context, id string) (*User, error) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "types:user.go:user:UserPGRead")
    }
	u := &User{}
	u, err := u.PGRead(ctx, id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return nil, err
	}
	return u, nil
}