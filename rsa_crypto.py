import random

def gcd( a, b ):
  while b:
    a, b = b, a % b
  return a

def miller_rabin_test( p, k=10 ):
    """
        Miller-Rabin primality test.
        Returning True if 'p' is probably prime.
        Returning False if the 'p' is composite.
    """
    if p <= 3:
        return False
    if p % 2 == 0:
        return False
    d = p - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for i in range( k+1 ):
        x = random.randint( 2, p-1 )
        if gcd( p, x ) > 1:
            return False
        if pow( x, d, p ) == 1 or pow( x, d, p ) == -1:
            return True
        for r in range( s ):
            x = pow( x, 2, p )
            if x == p - 1:
                return True
            elif x == 1:
                return False
            else:
                continue
    return False

get_random_n = lambda b:random.getrandbits( b ) | 1 << b - 1

def get_random_prime( b ):
    """ Getting the strong prime number. """
    x = get_random_n( b )
    while miller_rabin_test( x ) == False:
        x = get_random_n( b )
    i = 1
    while miller_rabin_test( 2*i*x + 1 ) == False:
        i += 1
    return 2*i*x + 1

def generate_prime_pairs( b ):
    """
        Genarating the pairs of random p, q, p1, q1.
                        p*q <= p1*q1
    """
    p = get_random_prime( b )
    q = get_random_prime( b )
    p1 = get_random_prime( b )
    q1 = get_random_prime( b )
    
    if p*q > p1*q1:
        p, p1 = p1, p
        q, q1 = q1, q
    return ( p, q, p1, q1 )

def public_key( p, q ):
    """ Counting the public key (n, e) """
    e = pow( 2, 16 ) + 1
    n = p*q
    return n, e

def find_inversed_element( a, m ):
    """ a*x == 1(mod m) """
    if a == 1:
        return 1
    return ( 1 - find_inversed_element( m % a, a ) * m ) // a + m

def secret_key( p, q ):
    """ Counting the 'd' value for secret key. """
    fn = ( p-1 )*( q-1 )
    d = find_inversed_element( pow( 2, 16 )+1, fn )
    return d

def encrypt( M, e, n ):
    """ Function returning the encrypted message """
    return pow( M, e, n )

def decrypt( C, d, n ):
    """ Function returning the decrypted message """
    return pow( C, d, n )

def sign( M, d, n ):
    """ Returning 'S' """
    return pow( M, d, n )

def verify( M, S, e, n ):
    """ Checking the digital signature """
    if M == pow( S, e, n ):
        return True
    else:
        return False

def send_key( k, n1, e1, d, n ):
    S = sign( k, d, n )
    k1 = encrypt( k, e1, n1 )
    S1 = encrypt( S, e1, n1 )
    return k1, S1

def receive_key( d1, k1, S1, n1, n, e ):
    k = decrypt( k1, d1, n1 )
    S = decrypt( S1, d1, n1 )
    print( "Received value:", k )
    if verify( k, S, e, n ) == True:
        return True
    else:
        return False

print( "Starting encryption ..." )
p = generate_prime_pairs( 256 )[ 0 ]
q = generate_prime_pairs( 256 )[ 1 ]
p1 = generate_prime_pairs( 256 )[ 2 ]
q1 = generate_prime_pairs( 256 )[ 3 ]

n = public_key( p, q )[ 0 ]
e = public_key( p, q )[ 1 ]
n1 = public_key( p1, q1 )[ 0 ]
e1 = public_key( p1, q1 )[ 1 ]

d = secret_key( p, q )
d1 = secret_key( p1, q1 )

print( "\nAbonent A: Sending a secret value 'k=62' to B.\nCreating a message '(k1, S1)' ..." )
k1 = send_key( 62, n1, e, d, n )[ 0 ]
print( "k1 =", k1 )
S1 = send_key( 62, n1, e, d, n)[ 1 ]
print( "S1 =", S1 )
print( "Abonent B: ecnrypting 'k' with my secret key 'd1' ..." )
print( "Abonent B: Checking A signature with his public key 'e' (authentification) ..." )
print( receive_key( d1, k1, S1, n1, n, e ) )
