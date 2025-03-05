package types

import (
	"context"
	"encoding/json"
	"fmt"
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
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:New")
    }
	user := c
	attributesPtr, err := c.Attributes.New(ctx, )
	if err != nil {
		return nil, err
	}
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes is nil")
	}
	user.Attributes = *attributesPtr
	user.Attributes.ContentType = "user"
	return &user, nil
}

func (c User) ToContent(ctx context.Context) (*Content, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:ToContent")
    }
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c User) Merge(ctx context.Context, old, new User) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:Merge")
    }
	attributesPtr, err := c.Attributes.Merge(ctx, old.Attributes, new.Attributes)
	if err != nil {
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
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:ToMSI")
    }
	return toMSI(ctx, c)
}

type Users []User

func (c Users) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:users:IsDocument")
    }
	return true
}

func (c Users) ToMSI(ctx context.Context) (map[string]interface{}, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:users:ToMSI")
    }
	return toMSI(ctx, c)
}

func NewUser(ctx context.Context) *User {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:NewUser")
    }
	u := User{}
	u.Attributes = *NewAttributes(ctx, nil)
	return &u
}

func (c User) Hydrate(ctx context.Context, msi map[string]interface{}) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:Hydrate")
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
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:GetUser")
    }
	usersPtr, err := GetUsers(ctx)
	if err != nil {
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
	return nil, fmt.Errorf("user id: %s not found", id)
}

func (c User) FindBy(ctx context.Context, jstring string) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:FindBy")
    }
	contentPtr, err := Content{}.FindBy(ctx, jstring)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	user := User{}
	err = json.Unmarshal(content.Content, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (c Users) In(ctx context.Context, id string) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:users.go:user:In")
    }
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Users) FindAll(ctx context.Context) (*Users, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:users:FindAll")
    }
	jstring := "{\"contentType\": \"location\"}"
	contents, err := Content{}.FindAll(ctx, jstring)
	if err != nil {
		return nil, err
	}
	users := c
	for _, content := range contents {
		user := User{}
		err = json.Unmarshal(content.Content, &user)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return &users, nil
}

func GetUsers(ctx context.Context) (*Users, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:GetUsers")
    }
	return Users{}.FindAll(ctx)
}

func (i User) MarshalBinary(ctx context.Context) ([]byte, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:MarshalBinary")
    }
	return json.Marshal(i)
}

func (c User) IsDocument(ctx context.Context) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:IsDocument")
    }
	return true
}

func (c User) HasRole(ctx context.Context, role string) bool {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:HasRole")
    }
	for _, v := range c.Roles {
		if v == role {
			return true
		}
	}
	return false
}

func (c User) PGHydrate(ctx context.Context, content Content) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:PGHydrate")
    }
	user := c
	attributesPtr := c.Attributes.PGHydrate(ctx, content)
	if attributesPtr == nil {
		return nil, fmt.Errorf("attributes are nil")
	}
	user.Attributes = *attributesPtr
	err := json.Unmarshal(content.Content, &user)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (c User) PGRead(ctx context.Context, id string) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:PGRead")
    }
	contentPtr, err := Content{}.Read(ctx, id)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	return c.PGHydrate(ctx, content)
}

func (c User) PGCreate(ctx context.Context) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:PGCreate")
    }
	err := Content{}.Create(ctx, c)
	if err != nil {
		return err
	}
	return nil
}

func (c User) PGUpdate(ctx context.Context) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:PGUpdate")
    }
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
		return err
	}
	return content.Update(ctx, c)
}

func (c User) PGDelete(ctx context.Context) error {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:PGDelete")
    }
	return Content{}.Delete(ctx, c.Attributes.Id)
}

func (c User) ScanRow(rows pgx.Rows) error {
	ctx := context.Background()
	defer rows.Close()
	content := Content{}
	err := rows.Scan(&content)
	if err != nil {
		return err
	}

	if content.ContentType == "user" {
		attributesPtr := c.Attributes.PGHydrate(ctx, content)
		if attributesPtr == nil {
			return fmt.Errorf("attributes is nil")
		}

		msi := make(map[string]interface{})
		err = json.Unmarshal(content.Content, &msi)
		if err != nil {
			return err
		}
		userPtr, err := c.Hydrate(ctx, msi)
		if err != nil {
			return err
		}
		if userPtr == nil {
			return fmt.Errorf("content body (user) is nil")
		}
		c = *userPtr
		c.Attributes = *attributesPtr
	}

	return nil
}

func (c User) Columns(ctx context.Context) []string {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:Columns")
    }
	columns := c.Attributes.Columns(ctx)
	return columns
}

func (c User) Values(ctx context.Context) []interface{} {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:Values")
    }
	values := c.Attributes.Values(ctx)
	return values
}

func UserPGRead(ctx context.Context, id string) (*User, error) {
    if v, ok := ctx.Value("updateCtx").(func(context.Context, string, string) context.Context); ok {
        ctx = v(ctx, "stack", "types:user.go:user:UserPGRead")
    }
	u := &User{}
	u, err := u.PGRead(ctx, id)
	if err != nil {
		return nil, err
	}
	return u, nil
}