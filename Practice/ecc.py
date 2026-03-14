class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def is_infinity(self):
        return self.x is None and self.y is None

    def __repr__(self):
        if self.is_infinity():
            return "Point(Infinity)"
        return f"Point({self.x}, {self.y})"

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y


class EllipticCurve:
    """
    Implementation of the curve y^2 = x^3 + ax + b (mod p).
    """
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def mod_inverse(self, a):
        return pow(a, -1, self.p)

    def add(self, P, Q):
        if P.is_infinity():
            return Q
        if Q.is_infinity():
            return P

        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return Point(None, None)

        if P != Q:
            numerator = (Q.y - P.y) % self.p
            denominator = (Q.x - P.x) % self.p
        else:
            numerator = (3 * P.x * P.x + self.a) % self.p
            denominator = (2 * P.y) % self.p

        lam = (numerator * self.mod_inverse(denominator)) % self.p

        x3 = (lam * lam - P.x - Q.x) % self.p
        y3 = (lam * (P.x - x3) - P.y) % self.p

        return Point(x3, y3)

    def multiply(self, k, P):
        result = Point(None, None)  # Infinity
        add_ptr = P

        while k > 0:
            if k & 1:
                result = self.add(result, add_ptr)
            add_ptr = self.add(add_ptr, add_ptr)
            k >>= 1

        return result


if __name__ == "__main__":
    # Curve: y^2 = x^3 + 2x + 2 (mod 17)
    curve = EllipticCurve(a=2, b=2, p=17)
    G = Point(5, 1)

    print("--- 1. Basic Verification ---")
    try:
        P2 = curve.multiply(2, G)
        P3 = curve.multiply(3, G)
        print(f"2G: {P2} (Expected: (6, 3))")
        print(f"3G: {P3} (Expected: (10, 6))")
    except Exception as e:
        print(f"Error: {e}")

    print("\n--- 2. ECDH Simulation ---")
    nA = 3
    nB = 7

    PA = curve.multiply(nA, G)  # Alice's Public Key
    PB = curve.multiply(nB, G)  # Bob's Public Key

    Secret_Alice = curve.multiply(nA, PB)
    Secret_Bob = curve.multiply(nB, PA)

    print(f"Alice's Secret: {Secret_Alice}")
    print(f"Bob's Secret:   {Secret_Bob}")

    if Secret_Alice == Secret_Bob and not Secret_Alice.is_infinity():
        print(">> SUCCESS: Shared secrets match!")
    else:
        print(">> FAIL: Logic incomplete or incorrect.")
