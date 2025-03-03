package types

import (
	"encoding/json"
	"fmt"
	"inventory/src/db"
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

func (c User) New() (*User, error) {
	user := c
	attributesPtr, err := c.Attributes.New()
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

func (c User) ToContent() (*Content, error) {
	content := Content{}
	content.Attributes = c.Attributes
	jbytes, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c User) Merge(old, new User) (*User, error) {
	attributesPtr, err := c.Attributes.Merge(old.Attributes, new.Attributes)
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

func (c User) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

type Users []User

func (c Users) IsDocument() bool {
	return true
}

func (c Users) ToMSI() (map[string]interface{}, error) {
	return toMSI(c)
}

func NewUser() *User {
	u := User{}
	u.Attributes = *NewAttributes(nil)
	return &u
}

func (c User) Hydrate(msi map[string]interface{}) (*User, error) {
	u := User{}
	if m, ok := msi["attributes"].(map[string]interface{}); ok {
		u.Attributes.MSIHydrate(m)
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

func GetUser(id string) (*User, error) {
	usersPtr, err := GetUsers()
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

func (c User) FindBy(jstring string) (*User, error) {
	contentPtr, err := Content{}.FindBy(jstring)
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

func (c Users) In(id string) bool {
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func GetUsers() (*Users, error) {
	users := Users{}
	redis, err := db.NewRedisClient()
	if err != nil {
		return nil, err
	}
	redisRepsonseString, err := redis.ReadJSONDocument("user", ".")
	if err != nil {
		return nil, err
	}
	if redisRepsonseString != nil {
		responseString := *redisRepsonseString
		if responseString != "" {
			err = json.Unmarshal([]byte(responseString), &users)
			if err != nil {
				return nil, err
			}
			return &users, nil
		}
	}
	return nil, fmt.Errorf("users not found")
}

func SetUser(u *User) (string, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		return "", err
	}

	if u != nil {
		value, err := json.Marshal(u)
		if err != nil {
			return "", err
		}
		d := db.Document{
			ID:    u.Id,
			Name:  "user",
			Value: string(value),
		}
		err = redis.UpdateDocument(&d)
		if err != nil {
			return "", err
		}
		return u.Id, nil
	}
	return "", fmt.Errorf("user is nil")
}

func CreateUser(u *User) (string, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		return "", err
	}

	if u != nil {
		value, err := json.Marshal(u)
		if err != nil {
			return "", err
		}
		d := db.Document{
			ID: u.Id,
			Name:  "user",
			Value: string(value),
		}
		err = redis.CreateDocument(&d)
		if err != nil {
			return "", err
		}
		return u.Id, nil
	}
	return "", fmt.Errorf("user is nil")
}

func DeleteUser(u *User) error {
	redis, err := db.NewRedisClient()
	if err != nil {
		return err
	}

	if u != nil {
		err = redis.DeleteDocument(u.Id)
		if err != nil {
			return err
		}
	}
	return nil
}

func (i User) MarshalBinary() ([]byte, error) {
	return json.Marshal(i)
}

func (c User) IsDocument() bool {
	return true
}

func (c User) HasRole(role string) bool {
	for _, v := range c.Roles {
		if v == role {
			return true
		}
	}
	return false
}

func (c User) PGHydrate(content Content) (*User, error) {
	user := c
	attributesPtr := c.Attributes.PGHydrate(content)
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

func (c User) PGRead(id string) (*User, error) {
	contentPtr, err := Content{}.Read(id)
	if err != nil {
		return nil, err
	}
	if contentPtr == nil {
		return nil, fmt.Errorf("content is nil")
	}
	content := *contentPtr
	return c.PGHydrate(content)
}

func (c User) PGCreate() error {
	err := Content{}.Create(c)
	if err != nil {
		return err
	}
	return nil
}

func (c User) PGUpdate() error {
	columns := c.Columns()
	values := c.Values()
	sets := []string{}
	if len(columns) == len(values) {
		for i := range columns {
			sets = append(sets, fmt.Sprintf("%s = ?", columns[i]))
		}
	}
	content, err := c.ToContent()
	if err != nil {
		return err
	}
	return content.Update(c)
}

func (c User) PGDelete() error {
	return Content{}.Delete(c.Attributes.Id)
}

func (c User) ScanRow(rows pgx.Rows) error {
	defer rows.Close()
	content := Content{}
	err := rows.Scan(&content)
	if err != nil {
		return err
	}

	if content.ContentType == "user" {
		attributesPtr := c.Attributes.PGHydrate(content)
		if attributesPtr == nil {
			return fmt.Errorf("attributes is nil")
		}

		msi := make(map[string]interface{})
		err = json.Unmarshal(content.Content, &msi)
		if err != nil {
			return err
		}
		userPtr, err := c.Hydrate(msi)
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

func (c User) Columns() []string {
	columns := c.Attributes.Columns()
	return columns
}

func (c User) Values() []interface{} {
	values := c.Attributes.Values()
	return values
}

func UserPGRead(id string) (*User, error) {
	u := &User{}
	u, err := u.PGRead(id)
	if err != nil {
		return nil, err
	}
	return u, nil
}