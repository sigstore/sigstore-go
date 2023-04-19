package policy

func VerifyKeyless(e any) error {
	policy, err := NewSigstorePolicy()
	if err != nil {
		return err
	}
	return policy.VerifyPolicy(e)
}
