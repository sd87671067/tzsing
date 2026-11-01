package store

import (
	"time"
	_ "time/tzdata"
)

// BillingStart uses calendar months and clamps days 29–31 to the month's last day.
func BillingStart(now time.Time, day int, zone string) time.Time {
	loc, e := time.LoadLocation(zone)
	if e != nil {
		loc = time.UTC
	}
	if day < 1 || day > 31 {
		day = 1
	}
	now = now.In(loc)
	makeStart := func(y int, m time.Month) time.Time {
		last := time.Date(y, m+1, 0, 0, 0, 0, 0, loc).Day()
		return time.Date(y, m, min(day, last), 0, 0, 0, 0, loc)
	}
	start := makeStart(now.Year(), now.Month())
	if now.Before(start) {
		start = makeStart(now.Year(), now.Month()-1)
	}
	return start
}
