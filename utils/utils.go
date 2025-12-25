// Package utils provides some helper function
package utils

import (
	"fmt"
	"strings"
)

func NetnsName(nodeName string) string {
	return "ns-" + nodeName
}

func NodeNameFromNetns(netns string) (string, error) {
	const prefix = "ns-"
	if !strings.HasPrefix(netns, prefix) {
		return "", fmt.Errorf("invalid netns name: %s", netns)
	}
	return netns[len(prefix):], nil
}

// EthName iface name in host
func EthName(nodeName string) string {
	return "v-" + nodeName
}

func NodeNameFromEth(eth string) (string, error) {
	const prefix = "v-"
	if !strings.HasPrefix(eth, prefix) {
		return "", fmt.Errorf("invalid eth name: %s", eth)
	}
	return eth[len(prefix):], nil
}

// PeerEthName iface name in node ns
func PeerEthName(nodeName string) string {
	return "p-" + nodeName
}

func NodeNameFromPeerEth(eth string) (string, error) {
	const prefix = "p-"
	if !strings.HasPrefix(eth, prefix) {
		return "", fmt.Errorf("invalid eth name: %s", eth)
	}
	return eth[len(prefix):], nil
}
