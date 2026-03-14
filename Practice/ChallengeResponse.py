import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (load_pem_public_key, load_pem_private_key)
from cryptography.exceptions import InvalidSignature

class CryptoHelper:

    @staticmethod
    def load_pem_public_key(pem_str: str):
        return load_pem_public_key(pem_str.encode())

    @staticmethod
    def load_pem_private_key(pem_str: str):
        return load_pem_private_key(pem_str.encode(), password=None)

    @staticmethod
    def sign(private_key, data) -> str:
        """
        Sign data using RSA-PSS + SHA256
        Return signature as hex string
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)

        signature = private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()

    @staticmethod
    def verify(public_key, data, signature_hex: str) -> bool:
        """
        Verify RSA-PSS + SHA256 signature
        """
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)

        try:
            public_key.verify(
                bytes.fromhex(signature_hex),
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

class Prover:
    def __init__(self, private_key_pem: str, certificate: dict):
        self.private_key = CryptoHelper.load_pem_private_key(private_key_pem)
        self.certificate = certificate

    def get_certificate(self) -> dict:
        return self.certificate

    def solve_challenge(self, nonce: str) -> str:
        return CryptoHelper.sign(self.private_key, nonce)

class Verifier:
    def __init__(self, ca_public_key_pem: str):
        # Root of Trust
        self.ca_public_key = CryptoHelper.load_pem_public_key(ca_public_key_pem)

    def verify_session(self, prover: Prover, nonce: str) -> bool:
        # 1. Get certificate
        cert = prover.get_certificate()
        info = cert["info"]
        signature = cert["signature"]

        # 2. Verify certificate using CA public key
        if not CryptoHelper.verify(self.ca_public_key, info, signature):
            print("Certificate verification failed")
            return False

        # 3. Extract user's public key
        user_public_key = CryptoHelper.load_pem_public_key(info["public_key"])

        # 4. Verify challenge-response
        response = prover.solve_challenge(nonce)

        if CryptoHelper.verify(user_public_key, nonce, response):
            print(f"Login successful for {info['id']}")
            return True
        else:
            print("Challenge response invalid")
            return False

DATASET = {
  "CA_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx9AYmIbNtcCcTMMUhclM\nlvCXXvf1TtVBsJIXQL56dhvPDrpm8XRiVYxbZdwpOhdgTrFvvkBysyHQgYS920Y0\nMv6cFY4nTgeVe4yuqfmqjdc4t2kdDIYbX1GoZKK9zMiIQub3LOd0FiNVbXov9RHU\njdARbka7wCb5wl6ijy5/YlLAdniF5OTurJCCpDKZ6T9kfqy2PxT+DYK33qNt+nYi\nzW2Jx/Ve2HXIxbk2ss8CqqZspxNM/A/oOS5mwl+ohRAGYEJJAE/u5l9PSdt3TQ8n\nXnQ/nIEJG388mQHDrRXfxJmXktkxlrPFpQt5ccWXAg8xbmbazXkEAsZjvzSVokYt\nNQIDAQAB\n-----END PUBLIC KEY-----\n",
  "ALICE_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC4SZmEXblCZufB\ndEy5/7vRa1wRTIj+fTnfBT8P8G7B6HeG/WbJFNgk418lmShbG6FKPP/wXGWJuGpE\nciFpy9N2B6LJgOxn/EFxgca326ONZaUmZT1DzDBkthJmzKMq++Wv0utpaCG9NJrs\nv3FbhsJqxCtUTkw5NeYAd1Ybcxt5itXatnsSrJUhF6MAxSQm6hL0RspJz65nk2Yy\nCTRD43NtK+gvbAY/fo/F4DiwNSeIfzX5t3C149LU3YsO5SImSLuIMBDWKYHWQ2za\n+Nd1FQQiXzWN3vCX1DA1MHl4P9FvrrqJnbXmlVucro21haXX58kXyzoc8SwcBLpf\nqGn34ziHAgMBAAECggEAWC7fxvcSLzQOsgN0s4wr04oMBDsbUquZhZ59DqN+XEtg\n5rda992BkCU84kDnjrEp/NwznFCaRcx5DUePtZBTH6eHveRzO076AdaXwGLZYE/D\nNxw6tLaAcbCuHYLOkUL4JapH+6hYfLEvcRoqpCFX5r73/N96meWwqYhxK7Fo9D8r\nMtQRGao1G6E0KAl9ouz+wa1U43QTw7I20yI/KyoXCX2Ahx9IrWzJcYUljXTduqcZ\n6aE5zRT51aIkADdwGeDLqh7+i+CxFd8MbwMc12NRcwW4E6yMBuMiEz3WmS8YiZKq\n+KWKnJUUqLT19Qb5OfNR5xoQANN2qdlkTtIDQMycAQKBgQDb8IlOZ/RFkm30mpGb\nGfmeOwvnEfNpK87ixkyb+18OIFYsafpsq+/iE7qO1lrhFEfq9CfcyGBRVgAZKpbN\nXIJ5UcTWu8Y5UQS4WUYYKyde5v3PZt27oXKzTfoDnsn0M9Muq0SzhrBS4Ofi+9Nf\nk8/6bRSCv/Grt9AeMr08kGmWgwKBgQDWgKXT/+reI2DulcNsech5kSn8KKLfbE58\nEBp8e+ce3vP0KHMJzJccuuje/SnbfIkmUE+MwgehBGIy6t+zNciQfaVoxgS+q8ZD\nBTp8uK+pwGpzh1varmuaPSgDPsTe3GtQN406QmD5mb0DMu36gNsbQEw1k5DP01sn\n3RAfqr3WrQKBgQChI8p1t5QwpOgKnnSvvog0de5yjaRZGc+qNr9KSRGLuAVq5Pql\nRBOs/+dfX42V+tX2Pow2JljrPqczyRBTxcOSP2aILWs98y4SItZIPtXJolOy8Rrj\nrZXr6OWUYXJ1iMLhHnpnTfdBwaYjl312OUXXpLOyWA8oULQaa/JZvTSfIQKBgQCN\nPIfz3z42pfTdI59ZfZaS9RJABkG3+whyh+for2yu1v6qdTfJ6/xT3n4W1XsKGiX0\nJE080UVUsB44iI5i4bb97L1ND5VwNoqE9pxcIv8HNrrg9u90PgR7umjuOhZG57uB\nRhKnma1gq+nYgWBQ4Sdj+iIz5MYlEXWj+drz/uigwQKBgDHFfCQBCJCGYF9nO8rg\nC2M9/lmGYCkQDwE/m+benFR8vHFhzyUMa9Gdy0vJxMuGZF7TROUVpD0lNydIjOJi\nuLhlN5XfM4hjactPPtl0N/pWO+uX/OeuwfE+9WHUdqNIsy3Fa4HlY3vqzInYjtVV\n0z8lfb/2nJ9i6t2/ilJsRvuv\n-----END PRIVATE KEY-----\n",
  "ALICE_CERTIFICATE": {
    "info": {
      "id": "Alice",
      "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuEmZhF25QmbnwXRMuf+7\n0WtcEUyI/n053wU/D/Buweh3hv1myRTYJONfJZkoWxuhSjz/8FxlibhqRHIhacvT\ndgeiyYDsZ/xBcYHGt9ujjWWlJmU9Q8wwZLYSZsyjKvvlr9LraWghvTSa7L9xW4bC\nasQrVE5MOTXmAHdWG3MbeYrV2rZ7EqyVIRejAMUkJuoS9EbKSc+uZ5NmMgk0Q+Nz\nbSvoL2wGP36PxeA4sDUniH81+bdwtePS1N2LDuUiJki7iDAQ1imB1kNs2vjXdRUE\nIl81jd7wl9QwNTB5eD/Rb666iZ215pVbnK6NtYWl1+fJF8s6HPEsHAS6X6hp9+M4\nhwIDAQAB\n-----END PUBLIC KEY-----\n"
    },
    "signature": "13e9e20359368ba6160ddbce11aea75523d9ff3b8259e9248dd35d20d7e2c9dbec919fd55b412b9b5a588db1d250e82622714b084d5c91e17eb5770a13977bdc9c4056e785d07da0e20457aca2f44cde04ca9f292eb6a2bdf8864a8df008fc4917c29e2dabb5b9d87fac3b63664c963ebc05ffb52de84e0cb5d7557a11168ef8c034da5db9b2c00d71bd14dd86b219e6acba39c5a89cd7a7b26ce4eb3a07a877f4b49313e70caf3bbb24d023035752d8c022d39fb03ac016269708c4a7997fe9c29686ecbd034e5fa45202aa2d698602d60b826de96dc60bf9f2803c49388af4144a64779096bb918192160e1f3a9b5ba39081805fab1931bdef7710f40633d9"
  },
  "BOB_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nMIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC1RjDJ6cY7rtXN\nP/UpifqY30HySGRyt8ATvlRN9o1/Cz/tr4ESNKVtFVKfgUEJBe+7zIP8MpCZXirE\nVLNNAt6J7QkpKHTjmgaLbke0KyW3WKvREqOZ3IK1Vdzxlkdfq2rof482w56E0QJi\nIGsL1pTmov7ylD3mpPKju7ukKOQrJATkmrudm13b3zd7yciA9Bo0oU+bQjxG9oDt\nolAjwS3Je04FTLPkA+owB1U0+BtoSK7+9VsXzxY8hwkXWWnEL0XKhYiKX09ykhVk\n+CJqrKF6liLzb1gp8XHT/BXdKYOYUz8hrGLjDbjnXnU5QWiubcADvQwQHVFWImNs\nUJOOZA6ZAgMBAAECggEAH4sTOk9fm0sVER4r/wpvfOJ8izhlokCvP8BC0z4v6QeA\nHFAJ2a0njA/FzNOlCXjq+nbgEKaL2uQz9O34NVJmfwGsMmlDzccjlGegOo23hmv7\nmenwZfmlFQDX7YIE8XTWqZZoyVLI5run+oNBnVG9n1SFoJiDHPte7Xbhc/NZoNfc\nuJ0sjCztdEV9/wQxow8kTR2MD9KXWKzHk35/p0foL/0R29dd6pnNjie72ohEgqay\nEB/55KzMR3r44x7HLFP5aFZUW5Fqbu4p49q3Thf8hfw3xJJxz2DZv3ppAt4kmQdN\nwzeqjDkEPPeU1eCW9WJzlemzzimP4TJqzVbVDWc8cQKBgQDZbvnTK+q9GXOp0RYS\naoTWWvD4Wtdbp8z87dzok3VvFOWcXiZUaecatSGraqHaoirjf/CGtLvWr05hf/l2\nRc+XJQs+GjaMfAMD5jar3yKEGm4xRpOTxmVW3HJuUAOELtHIZeNJvOr0WEL3F/Nj\nj6/jfzKZsvjt3k1/pqpIg/5QRwKBgQDVbVM1/rjDNovT9p4lcqJ2IPFqE9IRfFHT\nuqx2EfeH7xoB6E/oXgN8PisHNs3g/S1nIk6BIl0gYyALCPh1Q8IOctcfBoXVAPYh\n4ciqVmXekOWjLalt945qKDO2KLBhfBhX4L+KYWi0zPqWhWRcFdILBbles8MBzRVc\ndZt22rX6HwKBgQCs6ODI+vK4oIXndLu9t3Gd2UIp7mu2mrGcLjhvx9wqkw6plAGd\nPX6oMYTuAWVnLXE366VGKnH6Hv0Q8ila0dds1euj3kqk23W2Yxv1AAQ905rvmrV/\nXdV3BuYFLaIuOuFfIQ9ns1GRMKNIRoaqFTkFjECcE8R7vT4aFlryQe06vwKBgQCM\nFQiDrR+KCZg3VGwyeg5F6JNro3zCu01d4e1mRZ6pWvc//0HLa0FwX8GQJ5lzrdkK\nE0thmLN1GXqjo4yoMwQAxcGKfJaE2u+yB2bU3oZYUdRXiRXmtpCD/sUKL6StJ202\n6K3vXsYBvXRQLVdU1YGaeHRVwzkgSoJVwF984EqG0wKBgQClBK2cZQ2W5mOHInYf\n8St0wKJq/jO/3IvOWHsAD9bmM30RJ28dr1cH3l5aFB7DFn870PfaBboJdOCBOk9S\nE4p0hbewSIUzhqkJBlh/p/MmT8UNlI2E8zze3bc0XBGsxyyT1wUH3N4uy2RN7Wat\nK2Th5g17skg6FpKuWzXK8yyY8A==\n-----END PRIVATE KEY-----\n",
  "BOB_PUBLIC_KEY": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtUYwyenGO67VzT/1KYn6\nmN9B8khkcrfAE75UTfaNfws/7a+BEjSlbRVSn4FBCQXvu8yD/DKQmV4qxFSzTQLe\nie0JKSh045oGi25HtCslt1ir0RKjmdyCtVXc8ZZHX6tq6H+PNsOehNECYiBrC9aU\n5qL+8pQ95qTyo7u7pCjkKyQE5Jq7nZtd2983e8nIgPQaNKFPm0I8RvaA7aJQI8Et\nyXtOBUyz5APqMAdVNPgbaEiu/vVbF88WPIcJF1lpxC9FyoWIil9PcpIVZPgiaqyh\nepYi829YKfFx0/wV3SmDmFM/Iaxi4w245151OUForm3AA70MEB1RViJjbFCTjmQO\nmQIDAQAB\n-----END PUBLIC KEY-----\n"
}

def main():
    verifier = Verifier(DATASET["CA_PUBLIC_KEY"])

    print("\nScenario 1: Successful Login (Alice)")
    alice = Prover(
        DATASET["ALICE_PRIVATE_KEY"],
        DATASET["ALICE_CERTIFICATE"]
    )
    print("Result:", verifier.verify_session(alice, "nonce_123"))

    print("\nScenario 2: Impersonation Attack (Bob)")
    bob = Prover(
        DATASET["BOB_PRIVATE_KEY"],      # Bob's private key
        DATASET["ALICE_CERTIFICATE"]     # Alice's certificate
    )
    print("Result:", verifier.verify_session(bob, "nonce_456"))


if __name__ == "__main__":
    main()
