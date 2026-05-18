package expire

import "time"

func ExpiredUnix(exp int64) bool {
	return exp > 0 && time.Now().Unix() > exp
}

func DurationUntilUnix(exp int64) time.Duration {
	if exp <= 0 {
		return 0
	}
	delta := time.Until(time.Unix(exp+1, 0))
	if delta <= 0 {
		return time.Nanosecond
	}
	return delta
}
