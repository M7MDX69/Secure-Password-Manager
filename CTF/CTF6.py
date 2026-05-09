"""
RSA CTF

I tried 4 ideas:
- Pollard Rho
- Fermat
- Library
- Hybrid: Fermat then library

I will run the hybrid one only, because Fermat was supposed to work from the hint,
but it was slow, so I used the library as backup.
"""

import math
import random
import time


# given values from the challenge
n = 143991606075158483660871570161405209117
e = 65537
ciphertext = 34130411904650996210426832018051041635


def decrypt_rsa(n, e, ciphertext, p, q):
    # once p and q are known, RSA decryption is direct
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    m = pow(ciphertext, d, n)

    # convert the number back to readable text
    m_hex = hex(m)[2:]

    if len(m_hex) % 2 != 0:
        m_hex = "0" + m_hex

    try:
        text = bytes.fromhex(m_hex).decode()
    except Exception:
        text = str(m)

    return phi, d, m, m_hex, text


def print_solution(name, p, q, elapsed):
    print("\n---", name, "---")

    if p is None or q is None:
        print("could not factor n")
        print("time:", elapsed)
        return

    if p * q != n:
        print("wrong factors")
        print("p =", p)
        print("q =", q)
        return

    phi, d, m, m_hex, text = decrypt_rsa(n, e, ciphertext, p, q)

    print("p =", p)
    print("q =", q)
    print("difference =", abs(p - q))
    print("phi =", phi)
    print("d =", d)
    print("message int =", m)
    print("message hex =", m_hex)
    print("text =", text)
    print("time =", elapsed)


# ------------------------------------------------------------
# approach 1: Pollard Rho
# ------------------------------------------------------------

def pollard_rho_single_attempt(n):
    """
    I tried Pollard Rho because it is not just normal brute force.
    It uses random values and gcd to try to catch a factor.

    But for me it was not very stable. Sometimes it may work, sometimes it
    just takes too long, so I did not depend on it as the final run.
    """

    if n % 2 == 0:
        return 2

    x = random.randint(2, n - 2)
    y = x
    c = random.randint(1, n - 2)
    d = 1

    while d == 1:
        x = (x * x + c) % n
        y = (y * y + c) % n
        y = (y * y + c) % n

        d = math.gcd(abs(x - y), n)

    if d == n:
        return None

    return d


def pollard_rho_approach(n, max_attempts=20):
    # I retry it because one random try can fail
    for _ in range(max_attempts):
        factor = pollard_rho_single_attempt(n)

        if factor is not None and factor != 1 and factor != n:
            p = factor
            q = n // factor

            if p * q == n:
                return p, q

    return None, None


# ------------------------------------------------------------
# approach 2: Fermat
# ------------------------------------------------------------

def fermat_factorization_approach(n, max_iterations=100000):
    """
    Fermat should be useful if p and q are close.

    n = a^2 - b^2
    n = (a - b)(a + b)

    So:
    p = a - b
    q = a + b

    I expected this to work because the challenge says the primes are close.
    But actually it was slow. After factoring, the difference was:

    |p - q| = 798111620918682924

    So they are not close enough for Fermat to finish quickly.
    """

    a = math.isqrt(n)

    if a * a < n:
        a += 1

    for _ in range(max_iterations):
        b2 = a * a - n
        b = math.isqrt(b2)

        if b * b == b2:
            p = a - b
            q = a + b

            if p * q == n:
                return p, q

        a += 1

    return None, None


# ------------------------------------------------------------
# approach 3: library
# ------------------------------------------------------------

def library_factorization(n):
    """
    This is the easiest practical way.

    I used sympy because the manual methods were taking time.
    The bad thing is that it hides the details, so I kept the other methods
    in the file to show the attempts.
    """

    try:
        from sympy import factorint
    except ImportError:
        print("sympy is missing")
        print("install it with: py -m pip install sympy")
        return None, None

    factors = factorint(n)
    keys = list(factors.keys())

    if len(keys) != 2:
        return None, None

    p = keys[0]
    q = keys[1]

    if p * q == n:
        return p, q

    return None, None


# ------------------------------------------------------------
# approach 4: hybrid
# ------------------------------------------------------------

def hybrid_fermat_library_approach(n, fermat_limit=50000000000000):
    """
    This is the one I used finally.

    I first try Fermat because this matches the hint in the question.
    If it does not find the factors quickly, I move to the library.

    So it is not only library from the start, and also not waiting forever
    for Fermat.
    """

    print("trying Fermat first...")

    p, q = fermat_factorization_approach(n, max_iterations=fermat_limit)

    if p is not None and q is not None:
        print("Fermat worked")
        return p, q

    print("Fermat did not finish fast enough")
    print("using library now...")

    return library_factorization(n)


# ------------------------------------------------------------
# main
# ------------------------------------------------------------

if __name__ == "__main__":

    # Pollard Rho
    # I am not running it now because it may take time depending on random values.
    #
    # start = time.time()
    # p, q = pollard_rho_approach(n)
    # end = time.time()
    # print_solution("Pollard Rho", p, q, end - start)


    # Fermat
    # It matches the hint, but in this case it was too slow.
    #
    # start = time.time()
    # p, q = fermat_factorization_approach(n, max_iterations=1000000)
    # end = time.time()
    # print_solution("Fermat", p, q, end - start)


    # Library only
    # This works fast, but I want the final solution to show that I tried Fermat first.
    #
    # start = time.time()
    # p, q = library_factorization(n)
    # end = time.time()
    # print_solution("Library only", p, q, end - start)


    # Hybrid
    # This is my final chosen approach.
    start = time.time()
    p, q = hybrid_fermat_library_approach(n, fermat_limit=5000000)
    end = time.time()

    print_solution("Hybrid Fermat + Library", p, q, end - start)