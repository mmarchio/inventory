package errors

import (
	"log"
	"os"
	"runtime/debug"
)

var logger = log.New(os.Stdout, "\n\n", log.LstdFlags | log.Lshortfile)

type Error struct {
	Message string `json:"message"`
	Input interface{} `json:"input"`
	Trace string `json:"trace"`
	RequestUri string `json:"requestUri"`
	Package string `json:"package"`
	Function string `json:"function"`
	Struct string `json:"struct"`
	Error error
}

func (c Error) Err(e error) error {
	if e != nil {
		c.Error = e
		c.Message = e.Error()
		c.Trace = string(debug.Stack())
	
		logger.Printf("\n%#v\n", c)
		return e
	}
	return e
}
