// Copyright 2022 Northern.tech AS
//
//	Licensed under the Apache License, Version 2.0 (the "License");
//	you may not use this file except in compliance with the License.
//	You may obtain a copy of the License at
//
//	    http://www.apache.org/licenses/LICENSE-2.0
//
//	Unless required by applicable law or agreed to in writing, software
//	distributed under the License is distributed on an "AS IS" BASIS,
//	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//	See the License for the specific language governing permissions and
//	limitations under the License.
package keys

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadRsaPrivateKey(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		PrivateKey string
		Error      string
	}{
		{
			PrivateKey: PrivateKeyRSAPKCS1,
			Error:      "",
		},
		{
			PrivateKey: PrivateKeyRSA,
			Error:      "",
		},
		{
			PrivateKey: PrivateKeyECDSAP521,
			Error:      "key type not supported",
		},
		{
			PrivateKey: "randomGarbage",
			Error:      ErrMsgPrivKeyNotPEMEncoded,
		},
		{
			PrivateKey: `-----BEGIN PRIVATE KEY-----
randomPKCS8Garba
-----END PRIVATE KEY-----`,
			Error: "LoadRSAPrivate",
		},
		{
			PrivateKey: PublicKeyECDSAP521,
			Error:      "invalid PEM block header: PUBLIC KEY",
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(fmt.Sprintf("tc %d", i), func(t *testing.T) {
			t.Parallel()

			fd, err := os.CreateTemp(t.TempDir(), "private*.pem")
			if err != nil {
				panic(err)
			}
			_, err = fd.Write([]byte(tc.PrivateKey))
			fd.Close()
			if err != nil {
				panic(err)
			}

			key, err := LoadRSAPrivate(fd.Name())
			if tc.Error != "" {
				assert.ErrorContains(t, err, tc.Error)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, key)
			}
		})
	}

	t.Run("error/file not exist", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "not-exist.pem")
		_, err := LoadRSAPrivate(path)
		var expected *os.PathError
		assert.ErrorAs(t, err, &expected)
	})
}

const (
	PrivateKeyECDSAP521 = `-----BEGIN PRIVATE KEY-----
MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBb5dG63AsYEDyDzz2
8NxEY/K2X4zqpQ2RkCbwn3vsXHsFDWQMQjT6+hFs1aPoHquYcYXi4q9TJwHwcXzp
4J6J/uGhgYkDgYYABABjebTZZu6l6Orhb6NKwQ1YsIsgTg5BFJXuBRnApl0cm7hq
4lP9yH3qsW+okIs+r3YktApw45js5T0JWEqhGX021QGaZtw2ezL7PROkWV5A/ihc
VmpBmV0lMDAStu+Vlj9g5oM8TphpTXF24VXDk8O8+Swwq+Sp1mpRjWI9AizzBPMq
bQ==
-----END PRIVATE KEY-----`
	PublicKeyECDSAP521 = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAY3m02Wbupejq4W+jSsENWLCLIE4O
QRSV7gUZwKZdHJu4auJT/ch96rFvqJCLPq92JLQKcOOY7OU9CVhKoRl9NtUBmmbc
Nnsy+z0TpFleQP4oXFZqQZldJTAwErbvlZY/YOaDPE6YaU1xduFVw5PDvPksMKvk
qdZqUY1iPQIs8wTzKm0=
-----END PUBLIC KEY-----`
	PrivateKeyRSA = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDvaEqOq1uOTrSj
uAVIBKwQ7gspal8nPL4mKEuw2rO0upV7PSFKrANv7qyWy6ZzxoxbkdyqZFSQH3wS
z6uJEado0BfH8lF2U3W/+LRj5dPyVs2DTjLNRqCC7klhk5s5jtosEcnYechPHWPm
ggM5iJe7sni0JxE88KUwHVDjEydzbvRXTQSp2ccX6fAyMAWpNQr7AWfy4rHoWsfc
APIW/2ai6ufs+PXbNurjaxoZMxawaR5QM7kVhNFlfOSVq7TxRmfkZZDvVSGc4as2
g+clnlQsnM6C1UfercGwvkGfIIueUtN9SLZIgpuVTXLNswLOBjvOx/ESzFohmBUp
FgCnd+zxAgMBAAECggEAYuXhTtiI5NuskalWPS746bF8WOqBTlMwddDVm8Rs0i71
y0gwdYljjhy5nT2ZkGAn4Tf7QURbDoKDHb4+LUxmrMyx1j5K2qeVj+0sj8wEZyrm
kOR/5f7UFeJb2/w+9mMFy4i5qjx8u/n3J+TzchP0ImySolE1NMhwZNTncjaaaHtT
w2HInbdnfuMX8AKX5OSsYl6upE99JU9Vd53JZophu02wf8hdeobWbn4akxl4YGlO
3ZXYfE4L9+wpvB/weV1Eof7zn0+a4cCjilSySWEnOiBb/ZUg+mEdJA/eMR0rHmex
KbqZbzrk6AWxPmn4FOpD2PspFAHGrJ6lIoaCdOZ/dQKBgQD+wCIFDJ3tFjhAONoG
A8RNeYbsicx2gWRdwnlMKcqdGgvgWoyd1FQReB0+1MOp1csihmAsaOCYo6vmhDvq
WFEpJhCxiztXsYkfilB6xbQ2LhvTsXaPlJBA6SMDJ2XgA+NFCE9iYNjeurTp1/aj
LyETbU7RFkO06TcuJiofljDkcwKBgQDwlOS0B0DaDRekinD/BH7O22J5MDyUtxjO
xv8J00LfvXhxuDhEhTbT4mMJgTyCk0jgsFEpRbpMdqjWH6R+NbE1tekFpazkgYd9
z4HMLmic17XKOXWnledOaAkQB6USINp4GWLdGjiAeB3ELmmev91ZcfbU0d68LOo5
ODMLaD50CwKBgBeJWttKkiDAh8vvNL2PhYh+7OdXx+s/Ay3idOCDj/O531UIKKvA
XVAL3+/ZKoa7ePwknCgePHn9zTkMCJkbNcxuduZgbcgpX/jpB4yATakf03RYlhKn
8Df/EjwNXM04rrvHC8aUGhVh/KsKSABFr3GjDMAmpXTGg1GhNw0aDERfAoGBANYa
a/6bheeIR0YzvqP1iDTnoRdhCkj/OaCsEETaMmWT5SCvZcP1GfovOxw2W3eJRA5S
W6hzWXy7DT6iIm3/spmuLpbL/rXNYJtilIz1sDwE7M/vmvltutBYXdhaNVmQy1ye
mxFSSH5sZ3E0LOMOtRrpBVYZADRPdJM/pI2+U/ZJAoGBANVYEY7eJDSwnGcJFvf4
C4RrvNsyrQOLOF5+u5HAhWxrsRZXM+0I7Dqvid+/4yOVXY3Sdr6x0wOzjFMO1nxZ
vAodwAZdy5kWtFJjBOKruBAfkxxQ3dqTiofsm0Jp+h4SEnj/DsSLe3la2/BGXkhm
BWwgHX6PoC7FAdbJ3tILBxD2
-----END PRIVATE KEY-----`
	PrivateKeyRSAPKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA2Bkw7DIJg8+7hQPHSWp1YditDQTn/aF5Uc8yNlzkcCyi4lpY
hc7rKQkzPKRqopNRGhSPKpjRxt4OQz4ZRsAlDjQ5HpbknEZKOkWLbf8M2mG4u2wF
a4mdDZo3+rXwPyYffSlTbmovbg0MKcbV8Pqb6YeW/nF1zX4FSNcSvVY1CDHRdnp2
P16clWA4vUKSzOX6mxAuYjfuqE6SKtBDDQMtAWXqEvY1LYTBh0P3ny6VsHWhaecP
AmMJNyOkvXTHrrNI2cUSh+++ilbuTqTEi77Cw7jLPVcJr+IodcCER1oZ+9oyliLD
pdYNOlM26WGM2Ul48KH4ToAGRvJhfQjkla5/owIDAQABAoIBADCYqanULtOXmaH2
EZDvAeq5IWF2Iv2knHXLVI1pIm4fe5nPm2yr9bJKwVz31Isu+eQVj4SSzUodkbOJ
eYGxoCOrltTMNij2naaxEQPxgWBy7WoohqeCUPFIJyKYW6i32Aj7jCmec4AaKwwS
DPaeRQWlWk1qEoXduy6AP1SY2GA4+f8StG3+xMOWUlo3H1qIWUKwAcQnW5q2XWiF
0q2Nayuz/D17xG8IPVx/T3ZFA1t7P8Y5gjM0LHwf8GWu0KcAZaK2myrF67O3zhQe
7QSmMjiyKNymE/rUuLH+apx6HBCkpuvHVjbqG4strt2mUYsvmp6peyMPupqIm4Kl
xnq1CeECgYEA8hAzk7XD+ZwxxTCOvvq0tJqncaLQeW3HZMKo4nqNhnrjN21NW8Gg
xQ6wh+9uH4WHLHRLp0HNP/z9jLmFcHQygebcHDTQrwLGgAAy+nnxIh40cNWdR4B/
dJA6GxWkapgQw84byDXnJROYJRede4+ITlR0KOfPzERXTHfo5jXM0JsCgYEA5IpK
TE8dl/1DDaXCWzWW0orKslKl49/tIzZrV8JLiGvGehCOCAdgLOLMsE96iUQka9T2
us2120ltVjTuo95RulqJHcP5Hb6Z4jxK7ho5V28AzMpWJc3Sto8kS1Y+abAiGNyN
4NJqeDI+P2ATW8eQOJIsCrpT28Fyb3Ylov/nKZkCgYAKnX9FiQERHzJnjVuVMHVg
Pi/9ocA2swO9fXPeirVOInF4asirr3AXdC91pqBTrY1h+6+dpBsWJUgRNcmORuo4
HCGm8wH7ysldr6SMq3BRqLVwBU4iZpYwTGrf6TEOo6CIla9ONl7ul09iwQhc9Mxr
cvStHo1UTeLuLYv/HHjg5QKBgE2X8k/kUKzo7Ro2HD3xfOqw+s7+ppouzgm1kU5z
hkekJ/gLpN1u+6Vhv5Ng+L6gJymBXd/gtgzk6j1prVhvxBncYU982RjTPNYGGH6s
4qkf5Aqj7Anbzt3yzaTSfFBP39PHFlituD5k+KN10DzKDdpXLqLZzlz/WgYj+/VS
oz6JAoGAUaG6yncXpdmZmDfGhxwQtfZ5saJoj/KooKrnwerxoItDsUYLeIGmwDgV
yLMn8dwhm2xg8cjYsdR2uxEiBhGtA0VH6PnAnOU5Bnw4haOWiZ6D4zh7PAGh5jAW
j/ZC1+dPF08FixsQbPxEtTYZe9/9cvhbB0iVg5ir6X2Y7EfW+LY=
-----END RSA PRIVATE KEY-----`
)
