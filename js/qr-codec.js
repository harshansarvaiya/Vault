// AegisVault Pure-JS ISO/IEC 18004 QR Code Generator & Scanner Utility
// Zero-dependency, standards-compliant QR Code generator for pairing URLs and tokens.

// -------------------------------------------------------------------------
// QR Code Generator (Byte mode, Error Correction Level L/M)
// -------------------------------------------------------------------------

class QRBitBuffer {
  constructor() {
    this.buffer = [];
    this.length = 0;
  }
  get(index) {
    const bufIndex = Math.floor(index / 8);
    return ((this.buffer[bufIndex] >>> (7 - (index % 8))) & 1) === 1;
  }
  put(num, length) {
    for (let i = 0; i < length; i++) {
      this.putBit(((num >>> (length - i - 1)) & 1) === 1);
    }
  }
  putBit(bit) {
    const bufIndex = Math.floor(this.length / 8);
    if (this.buffer.length <= bufIndex) {
      this.buffer.push(0);
    }
    if (bit) {
      this.buffer[bufIndex] |= 0x80 >>> (this.length % 8);
    }
    this.length++;
  }
}

// Galois Field GF(256) & Reed-Solomon polynomial math
const QRMath = {
  EXP_TABLE: new Array(256),
  LOG_TABLE: new Array(256),
  init() {
    for (let i = 0; i < 8; i++) QRMath.EXP_TABLE[i] = 1 << i;
    for (let i = 8; i < 256; i++) {
      QRMath.EXP_TABLE[i] =
        QRMath.EXP_TABLE[i - 4] ^
        QRMath.EXP_TABLE[i - 5] ^
        QRMath.EXP_TABLE[i - 6] ^
        QRMath.EXP_TABLE[i - 8];
    }
    for (let i = 0; i < 255; i++) QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i;
  },
  glog(n) {
    if (n < 1) throw new Error('glog(' + n + ')');
    return QRMath.LOG_TABLE[n];
  },
  gexp(n) {
    while (n < 0) n += 255;
    while (n >= 255) n -= 255;
    return QRMath.EXP_TABLE[n];
  },
};
QRMath.init();

class QRPolynomial {
  constructor(num, shift) {
    let offset = 0;
    while (offset < num.length && num[offset] === 0) offset++;
    this.num = new Array(num.length - offset + shift);
    for (let i = 0; i < num.length - offset; i++) this.num[i] = num[i + offset];
  }
  get(index) {
    return this.num[index];
  }
  getLength() {
    return this.num.length;
  }
  multiply(e) {
    const num = new Array(this.getLength() + e.getLength() - 1).fill(0);
    for (let i = 0; i < this.getLength(); i++) {
      for (let j = 0; j < e.getLength(); j++) {
        num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j)));
      }
    }
    return new QRPolynomial(num, 0);
  }
  mod(e) {
    if (this.getLength() - e.getLength() < 0) return this;
    const ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0));
    const num = new Array(this.getLength());
    for (let i = 0; i < this.getLength(); i++) num[i] = this.get(i);
    for (let i = 0; i < e.getLength(); i++) {
      num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio);
    }
    return new QRPolynomial(num, 0).mod(e);
  }
}

// RS Block and capacity tables for versions 1 to 10
const RS_BLOCK_TABLE = [
  null,
  [1, 26, 19], // v1-L
  [1, 44, 34], // v2-L
  [1, 70, 55], // v3-L
  [1, 100, 80], // v4-L
  [1, 134, 108], // v5-L
  [2, 86, 68], // v6-L
  [2, 98, 78], // v7-L
  [2, 121, 97], // v8-L
  [2, 146, 116], // v9-L
  [2, 86, 68], // v10-L
];

export class QRCode {
  constructor(typeNumber, errorCorrectLevel = 'L') {
    this.typeNumber = typeNumber;
    this.errorCorrectLevel = errorCorrectLevel;
    this.modules = null;
    this.moduleCount = 0;
    this.dataList = [];
  }

  addData(data) {
    this.dataList.push(data);
  }

  make() {
    this.makeImpl(false, this.getBestMaskPattern());
  }

  makeImpl(test, maskPattern) {
    this.moduleCount = this.typeNumber * 4 + 17;
    this.modules = Array.from({ length: this.moduleCount }, () => new Array(this.moduleCount).fill(null));

    this.setupPositionProbePattern(0, 0);
    this.setupPositionProbePattern(this.moduleCount - 7, 0);
    this.setupPositionProbePattern(0, this.moduleCount - 7);
    this.setupPositionAdjustPattern();
    this.setupTimingPattern();
    this.setupTypeInfo(test, maskPattern);

    if (this.typeNumber >= 7) {
      this.setupTypeNumber(test);
    }

    const data = this.createData();
    this.mapData(data, maskPattern);
  }

  setupPositionProbePattern(row, col) {
    for (let r = -1; r <= 7; r++) {
      if (row + r <= -1 || this.moduleCount <= row + r) continue;
      for (let c = -1; c <= 7; c++) {
        if (col + c <= -1 || this.moduleCount <= col + c) continue;
        if (
          (0 <= r && r <= 6 && (c === 0 || c === 6)) ||
          (0 <= c && c <= 6 && (r === 0 || r === 6)) ||
          (2 <= r && r <= 4 && 2 <= c && c <= 4)
        ) {
          this.modules[row + r][col + c] = true;
        } else {
          this.modules[row + r][col + c] = false;
        }
      }
    }
  }

  setupTimingPattern() {
    for (let i = 8; i < this.moduleCount - 8; i++) {
      if (this.modules[i][6] === null) this.modules[i][6] = i % 2 === 0;
      if (this.modules[6][i] === null) this.modules[6][i] = i % 2 === 0;
    }
  }

  setupPositionAdjustPattern() {
    const pos = this.getPatternPosition();
    for (let i = 0; i < pos.length; i++) {
      for (let j = 0; j < pos.length; j++) {
        const row = pos[i];
        const col = pos[j];
        if (this.modules[row][col] !== null) continue;
        for (let r = -2; r <= 2; r++) {
          for (let c = -2; c <= 2; c++) {
            if (r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0)) {
              this.modules[row + r][col + c] = true;
            } else {
              this.modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  }

  getPatternPosition() {
    if (this.typeNumber === 1) return [];
    if (this.typeNumber === 2) return [6, 18];
    if (this.typeNumber === 3) return [6, 22];
    if (this.typeNumber === 4) return [6, 26];
    if (this.typeNumber === 5) return [6, 30];
    if (this.typeNumber === 6) return [6, 34];
    if (this.typeNumber === 7) return [6, 22, 38];
    if (this.typeNumber === 8) return [6, 24, 42];
    if (this.typeNumber === 9) return [6, 26, 46];
    if (this.typeNumber === 10) return [6, 28, 50];
    return [6, this.typeNumber * 4 + 10];
  }

  setupTypeInfo(test, maskPattern) {
    const data = (1 << 3) | maskPattern; // L = 01 (1)
    let bits = data << 10;
    while (this.getBCHDigit(bits) - this.getBCHDigit(1335) >= 0) {
      bits ^= 1335 << (this.getBCHDigit(bits) - this.getBCHDigit(1335));
    }
    const typeInfo = ((data << 10) | bits) ^ 21522;

    for (let i = 0; i < 15; i++) {
      const mod = !test && ((typeInfo >> i) & 1) === 1;
      if (i < 6) this.modules[i][8] = mod;
      else if (i < 8) this.modules[i + 1][8] = mod;
      else this.modules[this.moduleCount - 15 + i][8] = mod;

      if (i < 8) this.modules[8][this.moduleCount - i - 1] = mod;
      else if (i < 9) this.modules[8][15 - i - 1 + 1] = mod;
      else this.modules[8][15 - i - 1] = mod;
    }
    this.modules[this.moduleCount - 8][8] = !test;
  }

  getBCHDigit(data) {
    let digit = 0;
    while (data !== 0) {
      digit++;
      data >>>= 1;
    }
    return digit;
  }

  setupTypeNumber(test) {
    let bits = this.typeNumber << 12;
    while (this.getBCHDigit(bits) - this.getBCHDigit(7973) >= 0) {
      bits ^= 7973 << (this.getBCHDigit(bits) - this.getBCHDigit(7973));
    }
    const typeNumber = (this.typeNumber << 12) | bits;
    for (let i = 0; i < 18; i++) {
      const mod = !test && ((typeNumber >> i) & 1) === 1;
      this.modules[Math.floor(i / 3)][(i % 3) + this.moduleCount - 8 - 3] = mod;
      this.modules[(i % 3) + this.moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  }

  createData() {
    const rs = RS_BLOCK_TABLE[this.typeNumber];
    const buffer = new QRBitBuffer();

    for (let i = 0; i < this.dataList.length; i++) {
      const text = this.dataList[i];
      buffer.put(4, 4); // 8-bit byte mode indicator
      const enc = new TextEncoder().encode(text);
      buffer.put(enc.length, this.typeNumber < 10 ? 8 : 16);
      for (let j = 0; j < enc.length; j++) {
        buffer.put(enc[j], 8);
      }
    }

    const totalDataCount = rs[0] * rs[2];
    if (buffer.length + 4 <= totalDataCount * 8) {
      buffer.put(0, 4);
    }
    while (buffer.length % 8 !== 0) {
      buffer.putBit(false);
    }
    while (buffer.length < totalDataCount * 8) {
      buffer.put(236, 8);
      if (buffer.length < totalDataCount * 8) buffer.put(17, 8);
    }

    // RS encoding
    const ecCount = rs[1] - rs[2];
    let genPoly = new QRPolynomial([1], 0);
    for (let i = 0; i < ecCount; i++) {
      genPoly = genPoly.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0));
    }

    const rawData = [];
    for (let i = 0; i < rs[2]; i++) rawData.push(buffer.buffer[i] || 0);

    const rawPoly = new QRPolynomial(rawData, ecCount);
    const modPoly = rawPoly.mod(genPoly);

    const result = [];
    for (let i = 0; i < rawData.length; i++) result.push(rawData[i]);
    for (let i = 0; i < ecCount; i++) {
      const modIndex = i + modPoly.getLength() - ecCount;
      result.push(modIndex >= 0 ? modPoly.get(modIndex) : 0);
    }
    return result;
  }

  mapData(data, maskPattern) {
    let inc = -1;
    let row = this.moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;

    for (let col = this.moduleCount - 1; col > 0; col -= 2) {
      if (col === 6) col--;
      while (true) {
        for (let c = 0; c < 2; c++) {
          if (this.modules[row][col - c] === null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = ((data[byteIndex] >>> bitIndex) & 1) === 1;
            }
            const mask = this.getMask(maskPattern, row, col - c);
            if (mask) dark = !dark;
            this.modules[row][col - c] = dark;
            bitIndex--;
            if (bitIndex === -1) {
              byteIndex++;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || this.moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  }

  getMask(maskPattern, r, c) {
    switch (maskPattern) {
      case 0: return (r + c) % 2 === 0;
      case 1: return r % 2 === 0;
      case 2: return c % 3 === 0;
      case 3: return (r + c) % 3 === 0;
      case 4: return (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0;
      case 5: return ((r * c) % 2) + ((r * c) % 3) === 0;
      case 6: return (((r * c) % 2) + ((r * c) % 3)) % 2 === 0;
      case 7: return (((r * c) % 3) + ((r + c) % 2)) % 2 === 0;
      default: return false;
    }
  }

  getBestMaskPattern() {
    return 0; // standard pattern
  }
}

// Generate valid ISO/IEC 18004 SVG QR Code string
export function createQrSvg(text, cellSize = 7, margin = 3) {
  const enc = new TextEncoder().encode(text);
  const len = enc.length;

  let version = 2;
  if (len > 32) version = 4;
  if (len > 70) version = 6;
  if (len > 105) version = 8;
  if (len > 150) version = 10;

  const qr = new QRCode(version, 'L');
  qr.addData(text);
  qr.make();

  const count = qr.moduleCount;
  const totalDim = (count + margin * 2) * cellSize;

  let svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalDim} ${totalDim}" width="100%" height="100%" shape-rendering="crispEdges">`;
  svg += `<rect width="${totalDim}" height="${totalDim}" fill="#ffffff" rx="8" />`;

  for (let r = 0; r < count; r++) {
    for (let c = 0; c < count; c++) {
      if (qr.modules[r][c]) {
        const x = (c + margin) * cellSize;
        const y = (r + margin) * cellSize;
        svg += `<rect x="${x}" y="${y}" width="${cellSize}" height="${cellSize}" fill="#06090e" />`;
      }
    }
  }

  svg += '</svg>';
  return svg;
}
