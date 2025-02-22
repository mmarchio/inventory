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
	Error string `json:"error"`
	Input interface{} `json:"input"`
	Trace string `json:"trace"`
}

func Err(e error) error {
	if e != nil {
		r, w, _ := os.Pipe()
		os.Stderr = w
		debug.PrintStack()
		w.Close()

		var stderr bytes.Buffer
		io.Copy(&stderr, r)
		err := Error{
			Error: e.Error(),
			Trace: stderr.String(),
		}		
		out, outerr := json.Marshal(err)
		if outerr != nil {
			logger.Printf(outerr.Error())
			return outerr
		}
		logger.Printf(string(out))
		return e
	}
	return nil
}