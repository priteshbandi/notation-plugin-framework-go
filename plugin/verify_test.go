// Copyright The Notary Project Authors.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package plugin

import (
	"testing"
)

func TestValidate(t *testing.T) {
	v1 := VerifySignatureRequest{
		ContractVersion: "1.0",
		Signature: Signature{
			CriticalAttributes: CriticalAttributes{
				ContentType:   "someCT",
				SigningScheme: "someSigningScheme",
			},
			CertificateChain: [][]byte{[]byte("zap"), []byte("zop")},
		},
		TrustPolicy: TrustPolicy{
			SignatureVerification: []Capability{CapabilitySignatureGenerator},
		},
	}

	v2 := VerifySignatureRequest{
		ContractVersion: "2.0",
		Signature: Signature{
			CriticalAttributes:    CriticalAttributes{
				ContentType:   "someCT",
				SigningScheme: "someSigningScheme",
				Expiry:               nil,
				AuthenticSigningTime: nil,
				ExtendedAttributes:   nil,
			},
			UnprocessedAttributes: []string{"upa1", "upa2"},
			CertificateChain:      [][]byte{[]byte("zap"), []byte("zop")},,
		},
		TrustPolicy: TrustPolicy{
			TrustedIdentities:     []string{"trustedIdentity1", "trustedIdentity2"},
			SignatureVerification: []Capability{CapabilitySignatureGenerator, CapabilityRevocationCheckVerifier},
		},
		PluginConfig: map[string]string{"someKey": "someValue"},
	}

	if err := v.Validate(); err != nil {
		t.Fatalf("VerifySignatureRequest#Validate failed with error: %+v", err)
	}
}
