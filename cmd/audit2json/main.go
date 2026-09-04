package main

import (
	"bufio"
	"encoding/json"
	"flag"
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
	flags := flag.NewFlagSet("audit2json", flag.ContinueOnError)
	flags.SetOutput(stderr)
	sourceHost := flags.String("source-host", "", "source host override for canonical identity")
	if err := flags.Parse(args); err != nil {
		return err
	}

	var input io.Reader = stdin
	var file *os.File

	if flags.NArg() > 1 {
		return fmt.Errorf("usage: audit2json [options] [audit.log]")
	}
	if flags.NArg() == 1 {
		var err error
		file, err = os.Open(flags.Arg(0))
		if err != nil {
			return err
		}
		defer file.Close()
		input = file
	}

	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	assembler := audit.NewAssembler(0)
	canonicalOptions := audit.CanonicalOptions{Host: *sourceHost}
	emit := func(events []audit.AssembledEvent) error {
		for _, event := range events {
			if err := enc.Encode(audit.BuildCanonicalEvent(event, canonicalOptions)); err != nil {
				return err
			}
		}
		return nil
	}

	scanner := bufio.NewScanner(input)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		record, err := audit.ParseRecord(scanner.Text())
		if err != nil {
			fmt.Fprintln(stderr, "skip:", err)
			continue
		}
		if err := emit(assembler.Add(record)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Batch file and stdin modes flush incomplete events at EOF. The future
	// collector will call FlushExpired while waiting for more input.
	return emit(assembler.FlushAll())
}
