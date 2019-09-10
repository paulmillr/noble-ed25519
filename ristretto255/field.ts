const mask64Bits = (1n << 64n) - 1n;
const low51bitMask = (1n << 51n) - 1n;

export class FieldElement {
  // 𝔽p
  static readonly P = 2n ** 255n - 19n;

  static readonly D = new FieldElement(
    37095705934669439343138083508754565189542113879843219016388785533085940283555n
  );
  // Edwards `2*d` value, equal to `2*(-121665/121666) mod p`.
  static readonly D2 = new FieldElement(
    16295367250680780974490674513165176452449235426866156013048779062215315747161n
  );

  // sqrt(-1 % P)
  static readonly SQRT_M1 = new FieldElement(
    19681161376707505956807079304988542015446066515923890162744021073123829784752n
  );

  // `= 1/sqrt(a-d)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
  static readonly INVSQRT_A_MINUS_D = new FieldElement(
    54469307008909316920995813868745141605393597292927456921205312896311721017578n
  );

  // `= sqrt(a*d - 1)`, where `a = -1 (mod p)`, `d` are the Edwards curve parameters.
  static readonly SQRT_AD_MINUS_ONE = new FieldElement(
    25063068953384623474111414158702152701244531502492656460079210482610430750235n
  );

  // Prime subgroup. 25519 is a curve with cofactor = 8, so the order is:
  static readonly PRIME_ORDER =
    2n ** 252n + 27742317777372353535851937790883648493n;

  private static load8(input: Uint8Array, padding = 0) {
    return (
      BigInt(input[0 + padding]) |
      (BigInt(input[1 + padding]) << 8n) |
      (BigInt(input[2 + padding]) << 16n) |
      (BigInt(input[3 + padding]) << 24n) |
      (BigInt(input[4 + padding]) << 32n) |
      (BigInt(input[5 + padding]) << 40n) |
      (BigInt(input[6 + padding]) << 48n) |
      (BigInt(input[7 + padding]) << 56n)
    );
  }

  static fromBytes(bytes: Uint8Array) {
    const octet1 = this.load8(bytes, 0) & low51bitMask;
    const octet2 = (this.load8(bytes, 6) >> 3n) & low51bitMask;
    const octet3 = (this.load8(bytes, 12) >> 6n) & low51bitMask;
    const octet4 = (this.load8(bytes, 19) >> 1n) & low51bitMask;
    const octet5 = (this.load8(bytes, 24) >> 12n) & low51bitMask;
    return new FieldElement(
      octet1 +
        (octet2 << 51n) +
        (octet3 << 102n) +
        (octet4 << 153n) +
        (octet5 << 204n)
    );
  }

  static one() {
    return new FieldElement(1n);
  }

  static zero() {
    return new FieldElement(0n);
  }

  static mod(a: bigint, b: bigint) {
    const res = a % b;
    return res >= 0 ? res : b + res;
  }


  public readonly value: bigint;

  constructor(value: bigint) {
    this.value = FieldElement.mod(value, FieldElement.P);
  }

  toBytesBE(length: number = 0) {
    let hex = this.value.toString(16);
    hex = hex.length & 1 ? `0${hex}` : hex;
    hex = hex.padStart(length * 2, "0");
    const len = hex.length / 2;
    const u8 = new Uint8Array(len);
    for (let j = 0, i = 0; i < hex.length; i += 2, j++) {
      u8[j] = parseInt(hex[i] + hex[i + 1], 16);
    }
    return u8;
  }

  toBytesLE(length = 0) {
    return this.toBytesBE(length).reverse();
  }

  equals(other: FieldElement) {
    return this.value === other.value;
  }

  isNegative() {
    const bytes = this.toBytesLE();
    return Boolean(bytes[0] & 1);
  }

  isZero() {
    return this.value === 0n;
  }

  add(other: FieldElement) {
    return new FieldElement(this.value + other.value);
  }

  subtract(other: FieldElement) {
    return new FieldElement(this.value - other.value);
  }

  div(other: FieldElement) {
    return new FieldElement(this.value / other.value);
  }

  multiply(other: FieldElement) {
    return new FieldElement(this.value * other.value);
  }

  pow(power: bigint) {
    let res = FieldElement.one();
    let x = this as FieldElement;
    while (power > 0) {
      if (power & 1n) {
        res = res.multiply(x);
      }
      power >>= 1n;
      x = x.square();
    }
    return res;
  }

  pow2k(power: bigint) {
    let res = this as FieldElement;
    while (power-- > 0) {
      res = res.square();
    }
    return res;
  }

  invert() {
    const [t19, t3] = this.pow22501();
    return t19.pow(5n).multiply(t3);
  }

  negative() {
    return new FieldElement(-this.value);
  }

  square() {
    return this.multiply(this);
  }

  private pow22501() {
    const t0 = this.square();
    const t1 = t0.square().square();
    const t2 = this.multiply(t1);
    const t3 = t0.multiply(t2);
    const t4 = t3.square();
    const t5 = t2.multiply(t4);
    const t6 = t5.pow2k(5n);
    const t7 = t6.multiply(t5);
    const t8 = t7.pow2k(10n);
    const t9 = t8.multiply(t7);
    const t10 = t9.pow2k(20n);
    const t11 = t10.multiply(t9);
    const t12 = t11.pow2k(10n);
    const t13 = t12.multiply(t7);
    const t14 = t13.pow2k(50n);
    const t15 = t14.multiply(t13);
    const t16 = t15.pow2k(100n);
    const t17 = t16.multiply(t15);
    const t18 = t17.pow2k(50n);
    const t19 = t18.multiply(t13);
    return [t19, t3];
  }

  private powP58() {
    const [t19] = this.pow22501();
    return t19.pow2k(2n).multiply(this);
  }

  // Select sets v to a if cond == 1, and to b if cond == 0.
  select(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean) {
    return choice ? this : other;
  }

  condNegative(choice: 0n | 1n | 0 | 1 | boolean) {
    return this.negative().select(this, choice);
  }

  // CondSwap swaps a and b if cond == 1 or leaves them unchanged if cond == 0.
  condSwap(other: FieldElement, choice: 0n | 1n | 0 | 1 | boolean) {
    choice = BigInt(choice) as 0n | 1n;
    const mask = choice !== 0n ? mask64Bits : choice;
    const tmp = mask & (this.value ^ other.value);
    return [
      new FieldElement(this.value ^ tmp),
      new FieldElement(other.value ^ tmp)
    ];
  }

  sqrtRatio(v: FieldElement) {
    // Using the same trick as in ed25519 decoding, we merge the
    // inversion, the square root, and the square test as follows.
    //
    // To compute sqrt(α), we can compute β = α^((p+3)/8).
    // Then β^2 = ±α, so multiplying β by sqrt(-1) if necessary
    // gives sqrt(α).
    //
    // To compute 1/sqrt(α), we observe that
    //    1/β = α^(p-1 - (p+3)/8) = α^((7p-11)/8)
    //                            = α^3 * (α^7)^((p-5)/8).
    //
    // We can therefore compute sqrt(u/v) = sqrt(u)/sqrt(v)
    // by first computing
    //    r = u^((p+3)/8) v^(p-1-(p+3)/8)
    //      = u u^((p-5)/8) v^3 (v^7)^((p-5)/8)
    //      = (uv^3) (uv^7)^((p-5)/8).
    //
    // If v is nonzero and u/v is square, then r^2 = ±u/v,
    //                                     so vr^2 = ±u.
    // If vr^2 =  u, then sqrt(u/v) = r.
    // If vr^2 = -u, then sqrt(u/v) = r*sqrt(-1).
    //
    // If v is zero, r is also zero.
    const v3 = v.multiply(v).multiply(v);
    const v7 = v3.multiply(v3).multiply(v);
    let r = this.multiply(v7)
      .powP58()
      .multiply(this)
      .multiply(v3);
    const check = r.square().multiply(v);
    const i = FieldElement.SQRT_M1;
    const correctSignSqrt = check.equals(this);
    const flippedSignSqrt = check.equals(this.negative());
    const flippedSignSqrtI = check.equals(this.negative().multiply(i));
    const rPrime = FieldElement.SQRT_M1.multiply(r);
    r = rPrime.select(r, flippedSignSqrt || flippedSignSqrtI);
    r = r.condNegative(r.isNegative());
    const isNotZeroSquare = correctSignSqrt || flippedSignSqrt;
    return { isNotZeroSquare, value: r };
  }

  // Attempt to compute `sqrt(1/self)` in constant time.
  invertSqrt() {
    return FieldElement.one().sqrtRatio(this);
  }
}
