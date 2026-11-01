package store

import (
	"time"
	"tzsingbox/policy"
)

func BillingStart(now time.Time, day int, zone string) time.Time {
	return policy.BillingStart(now, day, zone)
}
