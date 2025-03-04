package types

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"github.com/labstack/echo/v4"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)

type IDocument interface {
	IsDocument() bool
	GetAttribute(string) (string, error)
}

func toMSI(ctx context.Context, c interface{}) (map[string]interface{}, error) {
	r := make(map[string]interface{})
	m, err := json.Marshal(c)
	if err != nil {
		return r, err
	}
	err = json.Unmarshal(m, &r)
	if err != nil {
		return r, err
	}
	return r, nil
}

func JSONValidate(ctx context.Context, data []byte, dest interface{}) bool {
	err := json.Unmarshal(data, &dest)
	return err == nil
}

func GetContent(ctx context.Context, id string) (*Content, error) {
	return Content{}.Read(ctx, id)
}

func GetMSIAttribute(ctx context.Context, name string, msi map[string]interface{}) (string, error) {
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		if v, ok := a[name].(string); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("attribute %s not found", name)
}

func GetContentIdFromUrl(ctx context.Context, c echo.Context) (string, error) {
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	url := c.Request().RequestURI
	segments := strings.Split(url, "/")
	if r.Match([]byte(segments[len(segments)-1])) {
		return segments[len(segments)-1], nil
	}
	return "", fmt.Errorf("content id not found in url")
}
