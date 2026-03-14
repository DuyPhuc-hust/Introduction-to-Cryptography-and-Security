import hashlib

def hash_n_times(value: str, n: int) -> str:
    """
    Apply SHA-256 hash n times recursively.
    """
    result = value.encode()
    for _ in range(n):
        result = hashlib.sha256(result).hexdigest().encode()
    return result.decode()

class Prover:
    def __init__(self, seed: str, count: int):
        """
        seed: secret key k
        count: initial counter N
        """
        self.seed = seed
        self.count = count

    def get_token(self) -> str:
        """
        Logic:
        1. Calculate t = H^count(seed)
        2. Decrement count
        3. Return t
        """
        if self.count < 0:
            raise ValueError("No tokens left")

        token = hash_n_times(self.seed, self.count)
        self.count -= 1
        return token

    def prepare_reseed(self, new_seed: str, new_count: int):
        """
        Logic:
        1. Generate auth_token from OLD chain
        2. new_anchor = H^(new_count + 1)(new_seed)
        3. Update internal state
        """
        auth_token = self.get_token()
        new_anchor = hash_n_times(new_seed, new_count + 1)

        self.seed = new_seed
        self.count = new_count

        return auth_token, new_anchor

class Verifier:
    def __init__(self, initial_vk: str):
        """
        initial_vk = H^(N+1)(k)
        """
        self.vk = initial_vk

    def verify(self, token: str) -> bool:
        """
        Verify SHA256(token) == vk
        """
        hashed = hashlib.sha256(token.encode()).hexdigest()
        if hashed == self.vk:
            self.vk = token
            return True
        return False

    def handle_reseed(self, auth_token: str, new_anchor: str) -> bool:
        """
        Verify reseed request
        """
        if self.verify(auth_token):
            self.vk = new_anchor
            return True
        return False

# Test Case 1: Manual Check
def run_test_case_1():
    seed = "hust"
    N = 2

    print("TEST CASE 1: MANUAL CHECK")
    print("H^0 =", seed)
    print("H^1 =", hash_n_times(seed, 1))
    print("H^2 =", hash_n_times(seed, 2))
    print("H^3 =", hash_n_times(seed, 3))

    prover = Prover(seed, N)
    verifier = Verifier(hash_n_times(seed, 3))

    token = prover.get_token()
    print("\nToken sent by Prover:", token)
    print("Verifier result:", verifier.verify(token))
    print("Updated vk:", verifier.vk)

# Test Case 2: Full Simulation
def run_simulation():
    print("\nTEST CASE 2: FULL SIMULATION")

    # Setup
    prover = Prover("A", 5)
    verifier = Verifier(hash_n_times("A", 6))

    # Login 1
    t1 = prover.get_token()
    print("Login 1:", verifier.verify(t1))

    # Login 2
    t2 = prover.get_token()
    print("Login 2:", verifier.verify(t2))

    # Replay attack
    print("Replay attack:", verifier.verify(t1))

    # Reseed
    auth_token, new_anchor = prover.prepare_reseed("B", 3)
    print("Reseed accepted:", verifier.handle_reseed(auth_token, new_anchor))

    # New login
    new_token = prover.get_token()
    print("New login after reseed:", verifier.verify(new_token))

if __name__ == "__main__":
    run_test_case_1()
    run_simulation()
