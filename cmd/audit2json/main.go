package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/marios-github/audit2json/internal/audit"
)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "audit2json:", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var input io.Reader = stdin
	var file *os.File

	if len(args) > 1 {
		return fmt.Errorf("usage: audit2json [audit.log]")
	}
	if len(args) == 1 {
		var err error
		file, err = os.Open(args[0])
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)

	pending := make(map[string][]audit.Record)
	scanner := bufio.NewScanner(input)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		record, err := audit.ParseRecord(line)
		if err != nil {
			fmt.Fprintln(stderr, "skip:", err)
			continue
		}

		pending[record.ID] = append(pending[record.ID], record)
		if record.Type != "EOE" {
			continue
		}

		event := audit.BuildEvent(pending[record.ID])
		if err := enc.Encode(event); err != nil {
			return err
		}
		delete(pending, record.ID)
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// File and stdin mode flush incomplete events at EOF. Live follow mode will
	// use a timeout-based flush in a later delivery.
	for id, records := range pending {
		if len(records) == 0 {
			continue
		}
		if err := enc.Encode(audit.BuildEvent(records)); err != nil {
			return err
		}
		delete(pending, id)
	}
	return nil
}
