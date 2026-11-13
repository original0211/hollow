// Package clock provides the monotonic, sleep-excluded time source the
// dead-man's switch is specified to use (TUN notes v2 §6, mandatory change
// D): heartbeat expiry must NOT be judged on a wall clock, and the elapsed
// accounting must exclude time the machine spent asleep — otherwise a
// sleep/wake cycle fakes either a dead peer or a live one.
//
// On Windows the source is QueryUnbiasedInterruptTime, the interrupt-time
// count that excludes sleep/hibernate. Elsewhere (dev/CI) it falls back to
// the process monotonic clock.
package clock

import "time"

var start = time.Now()

func fallbackMs() int64 { return time.Since(start).Milliseconds() }

// NowMs returns milliseconds on the sleep-excluded monotonic source.
func NowMs() int64 {
	return platformNowMs()
}

// Freshness judges a heartbeat received at local time lastRecvMs against
// the current local time: the peer is alive iff the gap is within the
// threshold. Both timestamps come from THIS side's clock (receipt times),
// so no cross-machine clock semantics are involved.
func Freshness(nowMs, lastRecvMs, thresholdMs int64) bool {
	if lastRecvMs <= 0 {
		return false
	}
	return nowMs-lastRecvMs <= thresholdMs
}
