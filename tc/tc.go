package tc

import (
	"bytes"
	"fmt"
	"log/slog"
	"os/exec"

	"kuro/config"
)

func run(cmd string) (string, error) {
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

// ApplyTc applies the TC (Traffic Control) rules defined in the configuration
// to the specified network interfaces and returns a list of interface names
// where the rules were successfully loaded.
func ApplyTc(config *config.Config) []string {
	var ifaces []string
	for _, rule := range config.Rules {

		if rule.NetQoS == nil {
			return nil
		}

		if rule.NetQoS.DelayMs == 0 &&
			rule.NetQoS.JitterMs == 0 &&
			rule.NetQoS.LossPct == 0 {
			continue
		}

		iface, err := applyNetemToIface(rule.Ifacename, rule)
		if err != nil {
			slog.Error("failed to apply netem", "iface", rule.Ifacename, "net_qos", *rule.NetQoS, "error", err)
		} else {
			ifaces = append(ifaces, iface)
		}
	}

	slog.Debug("ApplyTc", "ifaces", ifaces)
	return ifaces
}

func applyNetemToIface(iface string, rule config.Rule) (string, error) {
	// not fatal,_IGNORE error
	q := rule.NetQoS
	gress := rule.Gress // "ingress" / "egress" / "both"

	args := ""
	if q.DelayMs > 0 {
		if q.JitterMs > 0 {
			args += fmt.Sprintf(" delay %dms %dms", q.DelayMs, q.JitterMs)
		} else {
			args += fmt.Sprintf(" delay %dms", q.DelayMs)
		}
	}

	if q.LossPct > 0 {
		args += fmt.Sprintf(" loss %g%%", q.LossPct)
	}

	if args == "" {
		// no QoS to apply
		return iface, nil
	}

	// ----------------------------------------
	// EGRESS (root netem)
	// ----------------------------------------
	applyEgress := func() error {
		// qdisc root for egress
		cmd := fmt.Sprintf("tc qdisc replace dev %s root netem%s", iface, args)
		_, err := run(cmd)
		return err
	}

	// ----------------------------------------
	// INGRESS (ffff: netem)
	// ----------------------------------------
	applyIngress := func() error {
		// create ingress qdisc if not exists
		_, _ = run(fmt.Sprintf("tc qdisc add dev %s ingress", iface))

		// netem on ingress
		cmd := fmt.Sprintf("tc qdisc replace dev %s parent ffff: netem%s", iface, args)
		_, err := run(cmd)
		return err
	}

	// ----------------------------------------
	// MAIN DISPATCH
	// ----------------------------------------
	switch gress {
	case "egress":
		if err := applyEgress(); err != nil {
			return "", err
		}

	case "ingress":
		if err := applyIngress(); err != nil {
			return "", err
		}

	case "both":
		if err := applyEgress(); err != nil {
			return "", fmt.Errorf("egress apply failed: %w", err)
		}
		if err := applyIngress(); err != nil {
			return "", fmt.Errorf("ingress apply failed: %w", err)
		}

	default:
		return "", fmt.Errorf("unknown gress: %s", gress)
	}

	return iface, nil
}

func ClearNetems(ifaces ...string) error {
	var errs []error
	for _, iface := range ifaces {
		output, err := run(fmt.Sprintf("tc qdisc del dev %s root", iface))
		if err != nil {
			err = fmt.Errorf("failed to clear netem on %s: %w\noutput: %s", iface, err, output)
			slog.Error("failed to clear netem", "iface", iface, "error", err)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("multiple errors occurred during ClearNetems: %v", errs)
	}
	return nil
}
