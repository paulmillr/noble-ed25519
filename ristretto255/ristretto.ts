import { ProjectiveP3 } from "./jpoint";
import { FieldElement } from "./field";
import { isBytesEquals } from "./utils";

const ENCODING_LENGTH = 32;

export class RistrettoPoint {

  static one() {
    return new RistrettoPoint(ProjectiveP3.one());
  }

  static fromHash(hash: Uint8Array) {
    const r1 = FieldElement.fromBytes(hash.slice(0, ENCODING_LENGTH));
    const R1 = this.elligatorRistrettoFlavor(r1);
    const r2 = FieldElement.fromBytes(hash.slice(ENCODING_LENGTH, ENCODING_LENGTH * 2));
    const R2 = this.elligatorRistrettoFlavor(r2);
    return new RistrettoPoint(R1.add(R2));
  }

  // Computes the Ristretto Elligator map.
  // This method is not public because it's just used for hashing
  // to a point -- proper elligator support is deferred for now.
  private static elligatorRistrettoFlavor(r0: FieldElement) {
    const one = FieldElement.one();
    const oneMinusDSq = one.subtract(FieldElement.D.square());
    const dMinusOneSq = (FieldElement.D.subtract(one)).square();
    const r = FieldElement.SQRT_M1.multiply(r0.square());
    const NS = r.add(one).multiply(oneMinusDSq);
    let c = one.negative();
    const D = c.subtract(FieldElement.D.multiply(r)).multiply(r.add(FieldElement.D));
    let { isNotZeroSquare, value: S } = NS.sqrtRatio(D);
    let sPrime = S.multiply(r0);
    const sPrimeIsPos = !sPrime.isNegative();
    sPrime = sPrime.condNegative(sPrimeIsPos);
    S = S.select(sPrime, isNotZeroSquare);
    c = c.select(r, isNotZeroSquare);
    const NT = c.multiply(r.subtract(one)).multiply(dMinusOneSq).subtract(D);
    const sSquared = S.square();
    const projective = new ProjectiveP3(
      S.add(S).multiply(D),
      FieldElement.one().subtract(sSquared),
      NT.multiply(FieldElement.SQRT_AD_MINUS_ONE),
      FieldElement.one().add(sSquared),
    );
    return projective.toExtendedCompleted();
  }

  static fromBytes(bytes: Uint8Array) {
    // Step 1. Check s for validity:
    // 1.a) s must be 32 bytes (we get this from the type system)
    // 1.b) s < p
    // 1.c) s is nonnegative
    //
    // Our decoding routine ignores the high bit, so the only
    // possible failure for 1.b) is if someone encodes s in 0..18
    // as s+p in 2^255-19..2^255-1.  We can check this by
    // converting back to bytes, and checking that we get the
    // original input, since our encoding routine is canonical.
    const s = FieldElement.fromBytes(bytes);
    const sEncodingIsCanonical = isBytesEquals(s.toBytesLE(ENCODING_LENGTH), bytes);
    const sIsNegative = s.isNegative();
    if (!sEncodingIsCanonical || sIsNegative) {
      throw new Error("Cannot convert bytes to Ristretto Point");
    }
    const one = FieldElement.one();
    const s2 = s.square();
    const u1 = one.subtract(s2); // 1 + as²
    const u2 = one.add(s2); // 1 - as² where a=-1
    const squaredU2 = u2.square(); // (1 - as²)²
    // v == ad(1+as²)² - (1-as²)² where d=-121665/121666
    const v = u1.square().multiply(FieldElement.D.negative()).subtract(squaredU2);
    const { isNotZeroSquare, value: I } = v.multiply(squaredU2).invertSqrt(); // 1/sqrt(v*u_2²)
    const Dx = I.multiply(u2);
    const Dy = I.multiply(Dx).multiply(v); // 1/u2
    // x == | 2s/sqrt(v) | == + sqrt(4s²/(ad(1+as²)² - (1-as²)²))
    let x = s.add(s).multiply(Dx);
    const xIsNegative = BigInt(x.isNegative()) as 0n | 1n;
    x = x.condNegative(xIsNegative);
    // y == (1-as²)/(1+as²)
    const y = u1.multiply(Dy);
    // t == ((1+as²) sqrt(4s²/(ad(1+as²)² - (1-as²)²)))/(1-as²)
    const t = x.multiply(y);
    if (!isNotZeroSquare || t.isNegative() || y.isZero()) {
      throw new Error("Cannot convert bytes to Ristretto Point");
    }
    return new RistrettoPoint(new ProjectiveP3(x, y, one, t));
  }

  constructor(private point: ProjectiveP3) {}

  toBytes() {
    let { x, y, z, T } = this.point;
    // u1 = (z0 + y0) * (z0 - y0)
    const u1 = z.add(y).multiply(z.subtract(y));
    const u2 = x.multiply(y);
    // Ignore return value since this is always square
    const { value: invsqrt } = u2.square().multiply(u1).invertSqrt();
    const i1 = invsqrt.multiply(u1);
    const i2 = invsqrt.multiply(u2);
    const invertedZ = i1.multiply(i2).multiply(T);
    let invertedDenominator = i2;
    const iX = x.multiply(FieldElement.SQRT_M1);
    const iY = y.multiply(FieldElement.SQRT_M1);
    const enchantedDenominator = i1.multiply(FieldElement.INVSQRT_A_MINUS_D);
    const isRotated = BigInt(T.multiply(invertedZ).isNegative()) as 0n | 1n;
    x = iY.select(x, isRotated);
    y = iX.select(y, isRotated);
    invertedDenominator = enchantedDenominator.select(i2, isRotated);
    const yIsNegative = BigInt(x.multiply(invertedZ).isNegative()) as 0n | 1n;
    y = y.condNegative(yIsNegative);
    let s = z.subtract(y).multiply(invertedDenominator);
    const sIsNegative = BigInt(s.isNegative()) as 0n | 1n;
    s = s.condNegative(sIsNegative);
    return s.toBytesLE(ENCODING_LENGTH);
  }

  add(other: RistrettoPoint) {
    return new RistrettoPoint(this.point.add(other.point));
  }

  subtract(other: RistrettoPoint) {
    return new RistrettoPoint(this.point.subtract(other.point));
  }

  multiply(n: bigint) {
    return new RistrettoPoint(this.point.multiply(n));
  }

  equals(other: RistrettoPoint) {
    return this.point.equals(other.point);
  }
}

// https://tools.ietf.org/html/rfc8032#section-5.1
export const BASE_POINT = new RistrettoPoint(
  new ProjectiveP3(
    new FieldElement(15112221349535400772501151409588531511454012693041857206046113283949847762202n),
    new FieldElement(46316835694926478169428394003475163141307993866256225615783033603165251855960n),
    new FieldElement(1n),
    new FieldElement(46827403850823179245072216630277197565144205554125654976674165829533817101731n),
  )
);
