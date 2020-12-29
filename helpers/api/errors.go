package api

import (
	"errors"
)

// Static API errors.
var (
	ErrBadResponse = errors.New("bad response from API")
	ErrMissingData = errors.New("missing information to form request")
)
