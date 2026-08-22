package panda

import (
	"net/http"

	"github.com/LeeEirc/httpsig"
)

const (
	signHeaderRequestTarget = "(request-target)"
	signHeaderDate          = "date"
	signAlgorithm           = "hmac-sha256"
)

type ProfileAuth struct {
	KeyID    string
	SecretID string
}

func (auth *ProfileAuth) Sign(r *http.Request) error {
	headers := []string{signHeaderRequestTarget, signHeaderDate}
	signer, err := httpsig.NewRequestSigner(auth.KeyID, auth.SecretID, signAlgorithm)
	if err != nil {
		return err
	}
	return signer.SignRequest(r, headers, nil)
}
