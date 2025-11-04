import time
def rsa_decrypt(y, d, n):
    return pow(y, d, n)


def rsa_decrypt_crt(y, d, p, q):
    # Step 1: Compute dp and dq
    dp = d % (p - 1)
    dq = d % (q - 1)

    # Step 2: Compute partial results
    yp = pow(y, dp, p)
    yq = pow(y, dq, q)

    # Step 3: Combine using CRT
    q_inv = pow(q, -1, p)  
    h = (q_inv * (yp - yq)) % p
    x = (yq + h * q) % (p * q)

    return x


if __name__ == "__main__":
    large_p = 1234567890123456789012345686998765432109876543210987654347
    large_q = 9876543210987654321098765432312345678901234567890123456887
    large_n = large_p * large_q
    small_p = 13
    small_q = 11
    small_n = small_p * small_q
    e = 65537
    d = 183037555140763297287823421841341095154128759392745892977
    y = 12345678901234567890

    # Standard RSA large number
    start_time_1 = time.time()
    m_std_large = rsa_decrypt(y, d, large_n)
    end_time_1 = time.time()

    # CRT RSA large number
    start_time_2 = time.time()
    m_crt_large = rsa_decrypt_crt(y, d, large_p, large_q)
    end_time_2 = time.time()

    # Standard RSA small number
    start_time_3 = time.time()
    m_std_small = rsa_decrypt(y, d, small_n)
    end_time_3 = time.time()

    # CRT RSA small number
    start_time_4 = time.time()
    m_crt_small = rsa_decrypt_crt(y, d, small_p, small_q)
    end_time_4 = time.time()

    print("For large numbers")
    print("Standard RSA Decryption result:", m_std_large)
    print("CRT-based RSA Decryption result:", m_crt_large)
    print("Results comparison:", m_std_large == m_crt_large)
    print("Standard RSA Decryption time:", end_time_1 - start_time_1)
    print("CRT-based RSA Decryption time:", end_time_2 - start_time_2)
    print("For small numbers")
    print("Standard RSA Decryption result:", m_std_small)
    print("CRT-based RSA Decryption result:", m_crt_small)
    print("Results comparison:", m_std_small == m_crt_small)
    print("Standard RSA Decryption time:", end_time_3 - start_time_3)
    print("CRT-based RSA Decryption time:", end_time_4 - start_time_4)