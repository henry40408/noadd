package dns

// PatchTTL returns a copy of response with every TTL reduced by elapsedSeconds.
func PatchTTL(response []byte, elapsedSeconds uint32) []byte {
	patched := append([]byte(nil), response...)
	ApplyElapsed(patched, TTLOffsets(response), elapsedSeconds)
	return patched
}
