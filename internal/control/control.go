// Package control reserves a separate capability boundary for future node
// listing, configuration, routing, switching, validation and versioning.
// The monitoring application never constructs a writable sing-box client.
package control

import "errors"

var ErrReadOnly = errors.New("node control is not enabled in monitoring-only builds")

type Service interface {
	List() error
	Configuration() error
	Rules() error
	Switch() error
	Validate() error
	Versions() error
}
