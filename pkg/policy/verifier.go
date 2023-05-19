package policy

func VerifyKeyless(e SignedEntity) error {
	policy, err := NewSigstorePolicy()
	if err != nil {
		return err
	}
	return policy.VerifyPolicy(e)
}
