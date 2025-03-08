package types

import (
	"context"
	"inventory/src/errors"
	"inventory/src/util"
	"time"

	"github.com/google/uuid"
)

const FORMAT = "2006-01-02T15:04:05.000000000Z"

type Attributes struct {
	Id          string    `json:"id" db:"id"`
	ParentId    string    `json:"parentId" db:"parent_id"`
	RootId      string    `json:"rootId" db:"root_id"`
	CreatedAt   time.Time `json:"createdAt" db:"created_at"`
	UpdatedAt   time.Time `json:"updatedAt" db:"updated_at"`
	CreatedBy   string    `json:"createdBy" db:"created_by"`
	Owner       string    `json:"owner" db:"owner"`
	Name        string    `json:"name" db:"name"`
	ContentType string    `json:"contentType" db:"content_type"`
}

func (c Attributes) New(ctx context.Context) (*Attributes, error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:New")
	}
	a := c
	a.Id = uuid.NewString()
	a.CreatedAt = time.Now()
	a.UpdatedAt = time.Now()
	return &a, nil
}

func (c Attributes) Columns(ctx context.Context) []string {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:Columns")
	}
	cols := []string{
		"id",
		"parent_id",
		"root_id",
		"created_at",
		"updated_at",
		"created_by",
		"owner",
		"name",
		"content_type",
	}
	return cols
}

func (c Attributes) Values(ctx context.Context) []interface{} {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:Values")
	}
	cols := make([]interface{}, 0)
	cols = append(cols, c.Id)
	cols = append(cols, c.ParentId)
	cols = append(cols, c.RootId)
	cols = append(cols, c.CreatedAt.Format(FORMAT))
	cols = append(cols, c.UpdatedAt.Format(FORMAT))
	cols = append(cols, c.Owner)
	cols = append(cols, c.Name)
	cols = append(cols, c.ContentType)
	return cols
}

func (c Attributes) PGHydrate(ctx context.Context, content Content) *Attributes {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:PGHydrate")
	}
	c.Id = content.Id
	c.ParentId = content.ParentId
	c.RootId = content.RootId
	c.CreatedAt = content.CreatedAt
	c.UpdatedAt = content.UpdatedAt
	c.Owner = content.Owner
	c.Name = content.Name
	c.ContentType = content.ContentType
	return &c
}

func (c *Attributes) MSIHydrate(ctx context.Context, msi map[string]interface{}) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:MSIHydrate")
	}
	e := errors.Error{}
	if v, ok := msi["id"].(string); ok {
		c.Id = v
	}
	if v, ok := msi["createdAt"].(string); ok {
		t, err := time.Parse("2006-01-02T15:04:05.000000000Z", v)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
		c.CreatedAt = t
	}
	if v, ok := msi["updatedAt"].(string); ok {
		t, err := time.Parse("2006-01-02T15:04:05.000000000Z", v)
		if err != nil {
			e.Err(ctx, err)
			return err
		}
		c.UpdatedAt = t
	}
	if v, ok := msi["createdBy"].(string); ok {
		c.CreatedBy = v
	}
	if v, ok := msi["owner"].(string); ok {
		c.Owner = v
	}
	if v, ok := msi["name"].(string); ok {
		c.Name = v
	}
	if v, ok := msi["contentType"].(string); ok {
		c.ContentType = v
	}
	return nil
}

func (c Attributes) Merge(ctx context.Context, oldInput, newInput interface{}) (*Attributes, error) {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:Attributes:Merge")
	}
	e := errors.Error{}
	var old, new Attributes
	if o, ok := oldInput.(map[string]interface{}); ok {
		err := c.MSIHydrate(ctx, o)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		old = c
	}
	if o, ok := newInput.(map[string]interface{}); ok {
		err := c.MSIHydrate(ctx, o)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		new = c
	}
	if o, ok := oldInput.(Attributes); ok {
		old = o
	}
	if o, ok := newInput.(Attributes); ok {
		new = o
	}
	new.Id = old.Id
	new.CreatedAt = old.CreatedAt
	new.CreatedBy = old.CreatedBy
	new.UpdatedAt = time.Now()
	if new.Owner == "" {
		new.Owner = old.Owner
	}
	if new.Name == "" {
		new.Name = old.Name
	}
	if new.ContentType == "" {
		new.ContentType = old.ContentType
	}
	return &new, nil
}

func NewAttributes(ctx context.Context, createdBy *User) *Attributes {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:attributes.go:NewAttributes")
	}
	stack := []any{}
	if v, ok := ctx.Value("stack").([]any); ok {
		stack = append(stack, v...)
		ctx = context.WithValue(ctx, ckey, stack)
	}
	r := Attributes{
		Id:        uuid.NewString(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	if createdBy != nil {
		r.CreatedBy = createdBy.Id
		r.Owner = createdBy.Id
	} else {
		r.CreatedBy = r.Id
		r.Owner = r.Id
	}
	return &r
}
