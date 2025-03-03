package types

import (
	"encoding/json"
	"fmt"
	"inventory/src/db"
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

func toMSI(c interface{}) (map[string]interface{}, error) {
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

func JSONValidate(data []byte, dest interface{}) bool {
	err := json.Unmarshal(data, &dest)
	return err == nil
}

func GetContent(id string) (*map[string]interface{}, error) {
	redis, err := db.NewRedisClient()
	if err != nil {
		logger.Printf(err.Error())
		return nil, err
	}
	redisResponseString, err := redis.ReadJSONDocument("content", ".")
	if err != nil {
		logger.Printf(err.Error())
		return nil, err
	}
	if redisResponseString == nil {
		err := fmt.Errorf("redis response is nil")
		logger.Printf(err.Error())
		return nil, err
	}
	responseString := *redisResponseString
	if responseString == "" || responseString == " " {
		err := fmt.Errorf("empty redis response")
		logger.Printf(err.Error())
		return nil, err
	}
	msi := make([]map[string]interface{}, 0)
	if !JSONValidate([]byte(responseString), msi) {
		err := fmt.Errorf("redis response does not contain valid json\n\n %s", responseString)
		logger.Printf(err.Error())
		return nil, err
	}
	err = json.Unmarshal([]byte(responseString), &msi)
	if err != nil {
		logger.Printf(err.Error())
		return nil, err
	}
	for _, m := range msi {
		cid, err := GetMSIAttribute("id", m)
		if err != nil {
			logger.Printf(err.Error())
			return nil, err
		}
		if id == cid {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("content not found")
}

func GetMSIAttribute(name string, msi map[string]interface{}) (string, error) {
	if a, ok := msi["attributes"].(map[string]interface{}); ok {
		if v, ok := a[name].(string); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("attribute %s not found", name)
}

func GetContentIdFromUrl(c echo.Context) (string, error) {
	pattern := "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
	r := regexp.MustCompile(pattern)
	url := c.Request().RequestURI
	segments := strings.Split(url, "/")
	if r.Match([]byte(segments[len(segments)-1])) {
		return segments[len(segments)-1], nil
	}
	return "", fmt.Errorf("content id not found in url")
}
