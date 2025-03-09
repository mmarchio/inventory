package acl

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/types"
	"inventory/src/util"

	"github.com/google/uuid"
)

type Resource struct {
	types.Attributes
	Id  string `json:"id"`
	URL string `json:"url"`
}

func (c Resource) New(ctx context.Context) (*Resource,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resource:New")
	}
	resource := c
	resource.Id = uuid.NewString()
	return &resource, nil
}

func (c Resource) ToContent(ctx context.Context) (*types.Content,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:ToContent")
	}
	e := errors.Error{}
	content := types.Content{}
	content.Attributes.Id = c.Id
	content.Attributes.ContentType = "resource"
	jbytes, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	content.Content = jbytes
	return &content, nil
}

func (c Resource) PGRead(ctx context.Context) (*Resource,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGRead")
	}
	e := errors.Error{}
	contentPtr, err := types.Content{}.Read(ctx, c.Id)
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
	resource := c
	err = json.Unmarshal(content.Content, &resource)
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	return &resource, nil
}

func (c Resource) PGCreate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGCreate")
	}
	return types.Content{}.Create(ctx, c)
}

func (c Resource) PGUpdate(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGUpdate")
	}
	e := errors.Error{}
	contentPtr, err := c.ToContent(ctx)
	if err != nil {
		e.Err(ctx, err)
		return err
	}
	if contentPtr == nil {
		err = fmt.Errorf("content is nil")
		e.Err(ctx, err)
		return err
	}
	content := *contentPtr
	return content.Update(ctx, c)
}

func (c Resource) PGDelete(ctx context.Context) *map[string]errors.Error {

	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:PGDelete")
	}
	err := types.Content{}.Delete(ctx, c.Attributes.Id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
		return err
	}
	return nil
}

func (c Resource) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resource:IsDocument")
	}
	return true
}

func (c Resource) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resource:ToMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}

type Resources []Resource

func (c Resources) In(ctx context.Context, id string) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resources:In")
	}
	for _, o := range c {
		if o.Attributes.Id == id {
			return true
		}
	}
	return false
}

func (c Resources) IsDocument(ctx context.Context) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		_ = v(ctx, ckey, "acl:resource.go:Resources:IsDocument")
	}
	return true
}

func (c Resources) ToMSI(ctx context.Context) (map[string]interface{},*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:Resources:ToMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	b, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(b, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}

func FindResources(ctx context.Context) (*Resources,*map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "acl:resource.go:FindResources")
	}
	e := errors.Error{}
	content, err := types.Content{}.FindAll(ctx, "resource")
	if err != nil {
		e.Err(ctx, err)
		return nil, err
	}
	r := Resources{}
	for _, c := range content {
		resource := Resource{}
		err = json.Unmarshal(c.Content, &resource)
		if err != nil {
			e.Err(ctx, err)
			return nil, err
		}
		r = append(r, resource)
	}
	return &r, nil
}
