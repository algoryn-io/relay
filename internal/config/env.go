package config

import (
	"fmt"
	"reflect"
	"strings"
)

func (c *Config) ResolveEnv(getenv func(string) string) error {
	if c == nil {
		return errNilConfig
	}
	if getenv == nil {
		return fmt.Errorf("getenv: nil function")
	}

	return resolveEnvValue(reflect.ValueOf(c).Elem(), "config", getenv)
}

func resolveEnvValue(v reflect.Value, path string, getenv func(string) string) error {
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := t.Field(i)
			if !field.IsExported() {
				continue
			}

			fieldValue := v.Field(i)
			tagName := yamlFieldName(field.Tag.Get("yaml"))
			fieldPath := path + "." + tagName

			if strings.HasSuffix(tagName, "_env") && fieldValue.Kind() == reflect.String {
				envName := strings.TrimSpace(fieldValue.String())
				if envName != "" {
					resolved := getenv(envName)
					if resolved == "" {
						return fmt.Errorf("%s: environment variable %q is not set", fieldPath, envName)
					}

					targetName := strings.TrimSuffix(field.Name, "Env")
					target := v.FieldByName(targetName)
					if !target.IsValid() {
						target = v.FieldByName("Resolved" + targetName)
					}
					if target.IsValid() && target.CanSet() && target.Kind() == reflect.String {
						target.SetString(resolved)
					}
				}
			}

			if err := resolveEnvValue(fieldValue, fieldPath, getenv); err != nil {
				return err
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			if err := resolveEnvValue(v.Index(i), fmt.Sprintf("%s[%d]", path, i), getenv); err != nil {
				return err
			}
		}
	}

	return nil
}

func yamlFieldName(tag string) string {
	if tag == "" || tag == "-" {
		return "field"
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		return "field"
	}
	return name
}
