# TODO:Polynomial utils exist here


# Creates an object that includes convenience operations for numbers
# and polynomials in some prime field
class PrimeField:
    def __init__(self, modulus):
        assert pow(2, modulus, modulus) == 2
        self.modulus = modulus

    def add(self, x, y):
        return (x + y) % self.modulus

    def sub(self, x, y):
        return (x - y) % self.modulus

    def mul(self, x, y):
        return (x * y) % self.modulus

    def exp(self, x, p):
        return pow(x, p, self.modulus)

    # Modular inverse using the extended Euclidean algorithm
    def inv(self, a):
        pass

    def multi_inv(self, values):
        pass

    def div(self, x, y):
        pass

    # Evaluate a polynomial at a point
    def eval_poly_at(self, p, x):
        pass

    # Arithmetic for polynomials
    def add_polys(self, a, b):
        pass

    def sub_polys(self, a, b):
        pass

    def mul_by_const(self, a, c):
        pass

    def mul_polys(self, a, b):
        pass

    def div_polys(self, a, b):
        pass

    def mod_polys(self, a, b):
        pass

    # Build a polynomial from a few coefficients
    def sparse(self, coeff_dict):
        pass

    # Build a polynomial that returns 0 at all specified xs
    def zpoly(self, xs):
        pass

    # Given p+1 y values and x values with no errors, recovers the original
    # p+1 degree polynomial.
    # Lagrange interpolation works roughly in the following way.
    # 1. Suppose you have a set of points, eg. x = [1, 2, 3], y = [2, 5, 10]
    # 2. For each x, generate a polynomial which equals its corresponding
    #    y coordinate at that point and 0 at all other points provided.
    # 3. Add these polynomials together.

    def lagrange_interp(self, xs, ys):
        pass

    # Optimized poly evaluation for degree 4
    def eval_quartic(self, p, x):
        pass

    # Optimized version of the above restricted to deg-4 polynomials
    def lagrange_interp_4(self, xs, ys):
        pass

    # Optimized version of the above restricted to deg-2 polynomials
    def lagrange_interp_2(self, xs, ys):
        pass

    # Optimized version of the above restricted to deg-4 polynomials
    def multi_interp_4(self, xsets, ysets):
        pass
