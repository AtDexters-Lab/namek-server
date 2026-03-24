package tpm

// QuoteResult contains the verified results of a TPM quote.
type QuoteResult struct {
	// PCRValues contains the verified PCR register values.
	// nil if no PCR data was provided in the quote request.
	PCRValues map[int][]byte
}
