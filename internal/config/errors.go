package config

import (
	"errors"
	"fmt"
	"strings"
)

var errNilConfig = errors.New("config is nil")

type ValidationErrors struct {
	errs []error
}

func (v *ValidationErrors) Add(err error) {
	if err != nil {
		v.errs = append(v.errs, err)
	}
}

func (v *ValidationErrors) Addf(format string, args ...any) {
	v.errs = append(v.errs, fmt.Errorf(format, args...))
}

func (v *ValidationErrors) Err() error {
	if len(v.errs) == 0 {
		return nil
	}
	return v
}

func (v *ValidationErrors) Error() string {
	parts := make([]string, 0, len(v.errs))
	for _, err := range v.errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

func (v *ValidationErrors) Unwrap() []error {
	return v.errs
}
