package topo

import (
	"io"
	"log/slog"
	"os/exec"
	"syscall"

	"kuro/utils"
)

type baseNode struct {
	name     string
	ip       string
	nodeType string
}

type RuntimeNode interface {
	Name() string
	IP() string
	Type() string
	Run() error
	Stop() error
}

type ContainerNode struct {
	baseNode  baseNode
	container string
	image     string
}

func (n *ContainerNode) Name() string { return n.baseNode.name }
func (n *ContainerNode) IP() string   { return n.baseNode.ip }
func (n *ContainerNode) Type() string { return n.baseNode.nodeType }
func (n *ContainerNode) Run() error   { return nil }
func (n *ContainerNode) Stop() error  { return nil }

type ExecNode struct {
	baseNode baseNode
	exec     string
	args     []string
	cwd      string

	// save runtime information to stopping this process
	cmd *exec.Cmd
	pid int
}

func (n *ExecNode) Name() string { return n.baseNode.name }
func (n *ExecNode) IP() string   { return n.baseNode.ip }
func (n *ExecNode) Type() string { return n.baseNode.nodeType }
func (n *ExecNode) Run() error {
	slog.Info("Starting exec node",
		"node.name", n.Name(),
		"exec", n.exec,
		"args", n.args,
		"cwd", n.cwd,
	)

	cmd := exec.Command("ip", "netns", "exec", utils.NetnsName(n.Name()), n.exec)
	cmd.Args = append(cmd.Args, n.args...)

	if n.cwd != "" {
		cmd.Dir = n.cwd
	}

	cmd.Stdout = io.Discard // TODO: don't discard, redirect output
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		slog.Error("Failed to start exec node", "node.name", n.Name(), "error", err)
		return err
	}

	n.cmd = cmd
	n.pid = cmd.Process.Pid

	slog.Info("Exec node started", "node.name", n.Name(), "pid", n.pid)

	return nil
}

func (n *ExecNode) Stop() error {
	if n.cmd == nil || n.cmd.Process == nil {
		return nil
	}

	err := n.cmd.Process.Signal(syscall.SIGTERM)
	if err != nil {
		slog.Warn("SIGTERM failed, killing process", "node.name", n.Name(), "error", err)
		return n.cmd.Process.Kill()
	}

	slog.Info("Exec node stopped", "node.name", n.Name(), "pid", n.pid)
	return nil
}
