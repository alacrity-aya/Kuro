package tc

import (
	"bytes"
	"fmt"
	"os/exec"
)

func Run(cmd string) (string, error) {
	// prepend sudo
	fullCmd := "sudo " + cmd

	// use /bin/sh -c to support pipes, redirects etc
	c := exec.Command("sh", "-c", fullCmd)

	var out bytes.Buffer
	var stderr bytes.Buffer
	c.Stdout = &out
	c.Stderr = &stderr

	err := c.Run()

	output := out.String() + stderr.String()

	if err != nil {
		// return error with command + output
		return output, fmt.Errorf("command failed: %s\noutput:\n%s", fullCmd, output)
	}

	return output, nil
}
