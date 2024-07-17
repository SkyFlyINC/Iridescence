package Utils

import (
	"regexp"
	"strings"
)

func Utf8RuneCountInString(s string) int {
	return len([]rune(s))
}

func ContainsLetterAndNumber(s string) bool {
	match, _ := regexp.MatchString(`[a-zA-Z]+`, s)
	if !match {
		return false
	}
	match, _ = regexp.MatchString(`[0-9]+`, s)
	return match
}

func ContainsLowerAndUpperCase(s string) bool {
	return strings.ToLower(s) != s && strings.ToUpper(s) != s
}
