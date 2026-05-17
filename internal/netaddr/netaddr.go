package netaddr

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func ValidateHostPort(value string) error {
	return ValidateHostPortValue(value, false)
}

func ValidateListenHostPort(value string) error {
	return ValidateHostPortValue(value, true)
}

func ValidateListenHostPortAllowZero(value string) error {
	return validateHostPortValue(value, true, true)
}

func ValidateHostPortValue(value string, allowEmptyHost bool) error {
	return validateHostPortValue(value, allowEmptyHost, false)
}

func validateHostPortValue(value string, allowEmptyHost, allowZeroPort bool) error {
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("host:port 不能包含空白字符")
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if !allowEmptyHost && strings.TrimSpace(host) == "" {
		return fmt.Errorf("host 不能为空")
	}
	if strings.TrimSpace(host) != "" {
		if err := ValidateHostnameOrIP(host); err != nil {
			return err
		}
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("port 不能为空")
	}
	minPort := 1
	if allowZeroPort {
		minPort = 0
	}
	if p, err := strconv.Atoi(port); err != nil || p < minPort || p > 65535 {
		if allowZeroPort {
			return fmt.Errorf("port 必须在 0-65535 之间")
		}
		return fmt.Errorf("port 必须在 1-65535 之间")
	}
	return nil
}

func ValidateHostnameOrIP(host string) error {
	if net.ParseIP(host) != nil {
		return nil
	}
	host = NormalizeTargetHost(host)
	if !ValidHostname(host) {
		return fmt.Errorf("host %q 不是合法 IP 或 DNS 主机名", host)
	}
	return nil
}

func NormalizeTargetHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	return strings.TrimSuffix(host, ".")
}

func ValidHostname(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}
