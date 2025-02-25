package errors

import (
	"bytes"
	"encoding/json"
	"io"
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

		r, w, _ := os.Pipe()
		os.Stderr = w
		debug.PrintStack()
		w.Close()

		var stderr bytes.Buffer
		io.Copy(&stderr, r)
		out, outerr := json.Marshal(e)
		if outerr != nil {
			logger.Printf(outerr.Error())
			return outerr
		}
		logger.Printf(string(out))
		return c.Error
	}
	return e
}

func Err(e Error) error {
	if e.Error != nil {
		r, w, _ := os.Pipe()
		os.Stderr = w
		debug.PrintStack()
		w.Close()

		var stderr bytes.Buffer
		io.Copy(&stderr, r)
		out, outerr := json.Marshal(e)
		if outerr != nil {
			logger.Printf(outerr.Error())
			return outerr
		}
		logger.Printf(string(out))
		return e.Error
	}
	return nil
}