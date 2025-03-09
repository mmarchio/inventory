package types

import (
	"context"
	"encoding/json"
	"fmt"
	"inventory/src/errors"
	"inventory/src/util"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags|log.Lshortfile)
var ckey util.CtxKey = "stack"
var ukey util.CtxKey = "updateCtx"

type IDocument interface {
	IsDocument() bool
	GetAttribute(string) (string, *map[string]errors.Error)
}

func toMSI(ctx context.Context, c interface{}) (map[string]interface{}, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:common.go:toMSI")
	}
	e := errors.Error{}
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		e.Err(ctx, err)
		return r, err
	}
	return r, nil
}

func JSONValidate(ctx context.Context, data []byte, dest interface{}) bool {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:common.go:JSONValidate")
	}
	err := json.Unmarshal(data, &dest)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
	}
	return err == nil
}

func GetContent(ctx context.Context, id string) (*Content, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:common.go:GetContent")
	}
	content, err := Content{}.Read(ctx, id)
	if err != nil {
		e := errors.Error{}
		e.Err(ctx, err)
	}
	return content, nil
}

func GetMSIAttribute(ctx context.Context, name string, msi map[string]interface{}) (string, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:common.go:GetMSIAttribute")
	}
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		if v, ok := a[name].(string); ok {
			return v, nil
		}
	}
	err := fmt.Errorf("attribute %s not found", name)
	e := errors.Error{}
	e.Err(ctx, err)
	return "", err
}

func GetContentIdFromUrl(ctx context.Context, c echo.Context) (string, *map[string]errors.Error)
 {
	if v, ok := ctx.Value(ukey).(func(context.Context, util.CtxKey, string) context.Context); ok {
		ctx = v(ctx, ckey, "types:common.go:GetContentFromURL")
	}
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	url := c.Request().RequestURI
	segments := strings.Split(url, "/")
	if r.Match([]byte(segments[len(segments)-1])) {
		return segments[len(segments)-1], nil
	}
	err := fmt.Errorf("content id not found in url")
	e := errors.Error{}
	e.Err(ctx, err)
	return "", err
}
