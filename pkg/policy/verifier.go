package policy

func VerifyKeyless(e SignedEntity) error {
	policy, err := NewSigstorePublicPolicy()
	if err != nil {
		return err
	}
	return policy.VerifyPolicy(e)
}
