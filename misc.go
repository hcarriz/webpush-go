package webpush

import (
	"net/mail"
	"net/url"
	"strings"
)

func formatVAPIDJWTSubject(input string) (string, error) {

	input = strings.TrimPrefix(input, "mailto:")

	if _, err := mail.ParseAddress(input); err == nil {

		b := strings.Builder{}

		b.WriteString("mailto:")
		b.WriteString(input)

		return b.String(), nil
	}

	if result, err := url.Parse(input); err == nil && result.Scheme == "https" {
		return input, nil
	}

	return "", ErrInvalidSubscriber
}
