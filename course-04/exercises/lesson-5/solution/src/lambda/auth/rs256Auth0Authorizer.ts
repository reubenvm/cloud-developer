
import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify } from 'jsonwebtoken'
import { JwtToken } from '../../auth/JwtToken'

const cert = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIJG6zhuDyQOXdLMA0GCSqGSIb3DQEBCwUAMCwxKjAoBgNV
BAMTIWRldi02OGlyM2x6ZDFnbXpzdzVvLnVzLmF1dGgwLmNvbTAeFw0yMzA3MTEw
NjIwMThaFw0zNzAzMTkwNjIwMThaMCwxKjAoBgNVBAMTIWRldi02OGlyM2x6ZDFn
bXpzdzVvLnVzLmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMzzv6T+sLQnVO7yhPwh5EEA1UJ1+nWbSh4Wr6MiGhI7rKL6Rqci+3/UvcfW
kTRu3tK0PdrCrqyFNNichS4dcpHTaPyEY5/XNOYZgzZcMKNUQ+c0T+gSD4ex14m7
xfGhat+LMHfB0L44mjI6WaBtc86RhbLJaJN2SUMEo7T4RaiTK1zsSN/OW6PrQC/m
fb0jSiSRGDRurchrjU9ve4EBAEgXyrjG+9Tp9lbar88lUlrZeuQuxLc+CXuMmUjz
hhwjbux3FbpaerIQojo4k/4umEvcP3qoGktrwFhD24o4Dx/+mIFwO0ecvvIgqPCq
F5bVSXRvhIBofR1ixABhbwwQG50CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUbHLldsulfS0f4ssVWsQhovxVaoswDgYDVR0PAQH/BAQDAgKEMA0G
CSqGSIb3DQEBCwUAA4IBAQAuPqQ1rWsEu9Z7LBcy25zMYH1dmTA12V0AmzKGs3Yf
9jCXnjBJV3UngXbF91J1l3yC1CGsv7Xti79fLnTSnkfN+k5VFLRbZUvRzxJANLDu
ddxoUR7SA3M7lmMWVEyIKJUdmvsrgpY5yCFMC+aUIyWKKdLRIl/DNnGMrgLyMxp3
opamsMlF6Ecyh0Tmx/flt1nI0lCQms9dOsBCZhixqthQNOSetdlU4e8IfbJE0/MM
D3O1ffYeAcPwxrzt9EwwiTmRCsZX6YJvG+s7Dyt/wi/yhLR94fBHeP7rgv6Qa6+x
3fLI+Sk4stBzQIneiACBgzwmdPkjSlPdDpQPI1vAAB4A
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  try {
    const jwtToken = verifyToken(event.authorizationToken)
    console.log('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    console.log('User authorized', e.message)

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

function verifyToken(authHeader: string): JwtToken {
  if (!authHeader)
    throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return verify(token, cert, { algorithms: ['RS256'] }) as JwtToken
}
