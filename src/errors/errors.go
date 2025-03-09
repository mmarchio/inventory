package errors

import (
	"context"
	"fmt"
	"log"
	"os"
	"inventory/src/util"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)
var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type Error struct {
	Message string `json:"message"`
	Input interface{} `json:"input"`
	Trace []string `json:"trace"`
	RequestUri string `json:"requestUri"`
	Package string `json:"package"`
	Function string `json:"function"`
	Struct string `json:"struct"`
	File string `json:"file"`
	Recoverable bool `json:"recoverable"`
	Wrapper error
}

func (c Error) Error() string {
	return c.Wrapper.Error()
}

func (c *Error) IsRecoverable() {
	c.Recoverable = true
}

func (c *Error) GetCtxTrace(ctx context.Context) {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:errors.go:GetCtxTrace")
    }
	if v, ok := ctx.Value(ckey).([]string); ok {
		c.Trace = v
	}
}

func (c Error) Err(ctx context.Context, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:errors.go:Err")
		c.GetCtxTrace(ctx)
    }
	if e != nil {
		c.Wrapper = e
		c.Message = c.Wrapper.Error()
		if v, ok := ctx.Value(ckey).([]string); ok {
			c.Trace = v
		}
		logger.Printf("\n%#v\n", c)
		return c.Wrapper
	}
	return nil
}

func (c Error) ErrOrNil(ctx context.Context, ptr interface{}, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:error.go:Error:ErrOrNil")
		c.GetCtxTrace(ctx)
    }
	if ptr == nil {
		c.Wrapper = fmt.Errorf("pointer is nil")
		c.Message = c.Wrapper.Error()
		if v, ok := ctx.Value(ckey).([]string); ok {
			c.Trace = v
		}
		logger.Printf("\n%#v\n", c)
		return c.Wrapper
	}
	if e != nil {
		return c.Err(ctx, e)
	}
	return nil
}

func (c Error) New(ctx context.Context, f, p, fn, s string) map[string]Error {
	ce := make(map[string]Error)
	e := Error{
		File:     f,
		Package:  p,
		Function: fn,
		Struct:   s,
	}
	e.GetCtxTrace(ctx)
	if e.Struct != "" {
		ce[fmt.Sprintf("%s:%s:%s", p, s, fn)] = e
	} else {
		ce[fmt.Sprintf("%s:%s", p, fn)] = e
	}
	return ce
}

func ErrOrNil(ctx context.Context, ptr interface{}, e error) error {
    if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
        ctx = v(ctx, ckey, "errors:error.go:ErrOrNil")
    }
	err := Error{}
	return err.ErrOrNil(ctx, ptr, e)	
}
