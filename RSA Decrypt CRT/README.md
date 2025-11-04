# RSA Decryotion with CRT
## Data
1. **For large number**:
    - p = 1234567890123456789012345686998765432109876543210987654347
    - q = 9876543210987654321098765432312345678901234567890123456887
2. **For small number**:
    - p = 13
    - q = 11
3. **Parameters**:
    - e = 65537
    - d = 183037555140763297287823421841341095154128759392745892977
    - y = 12345678901234567890

## Test result
1. **For large number**:
    - Standard RSA Decryption result: 3981880512376770231868644762513132367118654738140290690882011276811020150152811914452745217465189846131539792543279 
    - CRT-based RSA Decryption result: 3981880512376770231868644762513132367118654738140290690882011276811020150152811914452745217465189846131539792543279
    - Result comparison: True
    - Standard RSA Decryption time: 0.00014519691467285156
    - CRT-based RSA Decryption time: 0.00012993812561035156
2. **For small number**:
    - Standard RSA Decryption result: 1
    - CRT-based RSA Decryption result: 1
    - Results comparison: True
    - Standard RSA Decryption time: 2.86102294921875e-06
    - CRT-based RSA Decryption time: 2.1457672119140625e-06
3. **Comparison**:
    - For large number ~ 1.12× faster
    - For small number ~ 1.33× faster
    - CRT optimization is slightly faster than standard RSA.
## Members
    - Nguyễn Duy Phúc 20235616
    - Nguyễn Hùng Quang 20235618
