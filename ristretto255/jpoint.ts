import { FieldElement } from "./field";

export class ProjectiveP1xP1 {
  static zero() {
    return new ProjectiveP1xP1(
      FieldElement.zero(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.one()
    );
  }

  constructor(
    public x: FieldElement,
    public y: FieldElement,
    public z: FieldElement,
    public T: FieldElement
  ) {}
}

export class ProjectiveP2 {
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP2(
      point.x.multiply(point.T),
      point.y.multiply(point.T),
      point.z.multiply(point.T)
    );
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveP2(point.x, point.y, point.z);
  }

  static zero() {
    return new ProjectiveP2(
      FieldElement.zero(),
      FieldElement.one(),
      FieldElement.one()
    );
  }

  constructor(
    public x: FieldElement,
    public y: FieldElement,
    public z: FieldElement
  ) {}

  double() {
    const squaredX = this.x.square();
    const squaredY = this.y.square();
    const squaredZ = this.z.square();
    const squaredZ2 = squaredZ.add(squaredZ);
    const xPlusYSquared = this.x.add(this.y).square();
    const y = squaredY.add(squaredX);
    const z = squaredY.subtract(squaredX);
    const x = xPlusYSquared.subtract(y);
    const T = squaredZ2.subtract(this.z);
    return new ProjectiveP1xP1(x, y, z, T);
  }
}

export class ProjectiveP3 {
  static fromP1xP1(point: ProjectiveP1xP1) {
    return new ProjectiveP3(
      point.x.multiply(point.T),
      point.y.multiply(point.z),
      point.z.multiply(point.T),
      point.x.multiply(point.y)
    );
  }

  static fromP2(point: ProjectiveP2) {
    return new ProjectiveP3(
      point.x.multiply(point.z),
      point.y.multiply(point.z),
      point.z.square(),
      point.x.multiply(point.y)
    );
  }

  static one() {
    return new ProjectiveP3(
      FieldElement.zero(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.zero()
    );
  }

  constructor(
    public x: FieldElement,
    public y: FieldElement,
    public z: FieldElement,
    public T: FieldElement
  ) {}

  toProjectiveNielsPoint() {
    return new ProjectiveP3(
      this.y.add(this.x),
      this.y.subtract(this.x),
      this.z,
      this.T.multiply(FieldElement.D2)
    );
  }

  toExtendedProjective() {
    return new ProjectiveP3(
      this.x.multiply(this.z),
      this.y.multiply(this.z),
      this.z.multiply(this.z),
      this.x.multiply(this.y)
    );
  }

  toExtendedCompleted() {
    return new ProjectiveP3(
      this.x.multiply(this.T),
      this.y.multiply(this.z),
      this.z.multiply(this.T),
      this.x.multiply(this.y)
    );
  }

  addCached(other: ProjectiveCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yPlusX);
    const MM = yMinusX.multiply(other.yMinusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(other.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(
      PP.subtract(MM),
      PP.add(MM),
      ZZ2.add(TT2),
      ZZ2.subtract(TT2)
    );
  }

  subtractCached(other: ProjectiveCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yMinusX);
    const MM = yMinusX.multiply(other.yPlusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(other.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(
      PP.subtract(MM),
      PP.add(MM),
      ZZ2.subtract(TT2),
      ZZ2.add(TT2)
    );
  }

  addAffine(other: AffineCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yPlusX);
    const MM = yMinusX.multiply(other.yMinusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(this.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(
      PP.subtract(MM),
      PP.add(MM),
      ZZ2.add(TT2),
      ZZ2.subtract(TT2)
    );
  }

  subtractAffine(other: AffineCached) {
    const yPlusX = this.y.add(this.x);
    const yMinusX = this.y.subtract(this.x);
    const PP = yPlusX.multiply(other.yMinusX);
    const MM = yMinusX.multiply(other.yPlusX);
    const TT2 = this.T.multiply(other.T2d);
    const ZZ = this.z.multiply(this.z);
    const ZZ2 = ZZ.add(ZZ);
    return new ProjectiveP1xP1(
      PP.subtract(MM),
      PP.add(MM),
      ZZ2.subtract(TT2),
      ZZ2.add(TT2)
    );
  }

  add(other: ProjectiveP3) {
    const cached = ProjectiveCached.fromP3(other);
    const result = this.addCached(cached);
    return ProjectiveP3.fromP1xP1(result);
  }

  subtract(other: ProjectiveP3) {
    const cached = ProjectiveCached.fromP3(other);
    const result = this.subtractCached(cached);
    return ProjectiveP3.fromP1xP1(result);
  }

  double() {
    const x2 = this.x.square();
    const y2 = this.y.square();
    const z2 = this.z.square();
    const xPlusY2 = this.x.add(this.y).square();
    const y2PlusX2 = y2.add(x2);
    const y2MinusX2 = y2.subtract(x2);
    return new ProjectiveP3(
      xPlusY2.subtract(y2MinusX2),
      y2PlusX2,
      y2MinusX2,
      z2.subtract(y2MinusX2)
    );
  }

  negative() {
    return new ProjectiveP3(
      this.x.negative(),
      this.y,
      this.z,
      this.T.negative()
    );
  }

  multiply(n: bigint) {
    let q = ProjectiveP3.one();
    for (let db: ProjectiveP3 = this; n > 0n; n >>= 1n, db = db.double()) {
      if ((n & 1n) === 1n) {
        q = q.add(db);
      }
    }
    return q;
  }

  // by @ebfull
  // https://github.com/dalek-cryptography/curve25519-dalek/pull/226/files
  equals(other: ProjectiveP3) {
    const t1 = this.x.multiply(other.z);
    const t2 = other.x.multiply(this.z);
    const t3 = this.y.multiply(other.z);
    const t4 = other.y.multiply(this.z);
    return t1.equals(t2) && t3.equals(t4);
  }
}

export class ProjectiveCached {
  static one() {
    return new ProjectiveCached(
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.zero()
    );
  }

  static fromP3(point: ProjectiveP3) {
    return new ProjectiveCached(
      point.y.add(point.x),
      point.y.subtract(point.x),
      point.z,
      point.T.multiply(FieldElement.D2)
    );
  }

  constructor(
    public yPlusX: FieldElement,
    public yMinusX: FieldElement,
    public z: FieldElement,
    public T2d: FieldElement
  ) {}

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: ProjectiveCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = this.yPlusX.select(other.yPlusX, cond);
    const yMinusX = this.yMinusX.select(other.yMinusX, cond);
    const z = this.z.select(other.z, cond);
    const T2d = this.T2d.select(other.T2d, cond);
    return new ProjectiveCached(yPlusX, yMinusX, z, T2d);
  }

  // Select sets v to a if cond == 1 and to b if cond == 0.
  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
    const T2d = this.T2d.condNegative(cond);
    return new ProjectiveCached(yPlusX, yMinusX, this.z, T2d);
  }
}

export class AffineCached {
  static fromP3(point: ProjectiveP3) {
    const yPlusX = point.y.add(point.x);
    const yMinusX = point.y.subtract(point.x);
    const T2d = point.T.multiply(FieldElement.D2);
    const invertedZ = point.z.invert();
    const newYPlusX = yPlusX.multiply(invertedZ);
    const newYMinusX = yMinusX.multiply(invertedZ);
    const newT2D = T2d.multiply(invertedZ);
    return new AffineCached(newYPlusX, newYMinusX, newT2D);
  }

  static one() {
    return new AffineCached(
      FieldElement.one(),
      FieldElement.one(),
      FieldElement.zero()
    );
  }

  constructor(
    public yPlusX: FieldElement,
    public yMinusX: FieldElement,
    public T2d: FieldElement
  ) {}

  // Select sets v to a if cond == 1 and to b if cond == 0.
  select(other: AffineCached, cond: 0 | 1 | 0n | 1n | boolean) {
    const yPlusX = this.yPlusX.select(other.yPlusX, cond);
    const yMinusX = this.yMinusX.select(other.yMinusX, cond);
    const T2d = this.T2d.select(other.T2d, cond);
    return new AffineCached(yPlusX, yMinusX, T2d);
  }

  condNegative(cond: 0 | 1 | 0n | 1n | boolean) {
    const [yPlusX, yMinusX] = this.yPlusX.condSwap(this.yMinusX, cond);
    const T2d = this.T2d.condNegative(cond);
    return new AffineCached(yPlusX, yMinusX, T2d);
  }
}
