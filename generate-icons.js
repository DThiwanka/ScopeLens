const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

function createPng(size) {
  const width = size;
  const height = size;

  // Pixel buffer (RGBA)
  const buffer = Buffer.alloc(width * height * 4);

  // Background: Rounded rectangle in amber (#f2b544)
  // Text or icon: Dark center (#0b0e13)
  const amber = [0xf2, 0xb5, 0x44, 0xff];
  const dark = [0x0b, 0x0e, 0x13, 0xff];
  const radius = Math.floor(size * 0.22);

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const idx = (y * width + x) * 4;

      // Check rounded corner distance
      const dx = Math.max(radius - x, 0, x - (width - 1 - radius));
      const dy = Math.max(radius - y, 0, y - (height - 1 - radius));
      const dist = Math.sqrt(dx * dx + dy * dy);

      if (dist > radius) {
        // Transparent outside rounded corners
        buffer[idx] = 0;
        buffer[idx + 1] = 0;
        buffer[idx + 2] = 0;
        buffer[idx + 3] = 0;
        continue;
      }

      // Lens circle symbol inside
      const centerX = width / 2;
      const centerY = height / 2;
      const cDist = Math.hypot(x - centerX, y - centerY);
      const outerR = size * 0.35;
      const innerR = size * 0.22;

      // Lens ring
      if (cDist >= innerR && cDist <= outerR) {
        buffer[idx] = dark[0];
        buffer[idx + 1] = dark[1];
        buffer[idx + 2] = dark[2];
        buffer[idx + 3] = dark[3];
      } 
      // Handle of the magnifying glass / lens
      else if (x >= centerX + size * 0.18 && x <= centerX + size * 0.38 &&
               y >= centerY + size * 0.18 && y <= centerY + size * 0.38 &&
               Math.abs((x - centerX) - (y - centerY)) < size * 0.08) {
        buffer[idx] = dark[0];
        buffer[idx + 1] = dark[1];
        buffer[idx + 2] = dark[2];
        buffer[idx + 3] = dark[3];
      }
      else {
        buffer[idx] = amber[0];
        buffer[idx + 1] = amber[1];
        buffer[idx + 2] = amber[2];
        buffer[idx + 3] = amber[3];
      }
    }
  }

  // Build raw uncompressed scanlines with filter byte 0
  const scanlines = Buffer.alloc(height * (width * 4 + 1));
  for (let y = 0; y < height; y++) {
    const rowOffset = y * (width * 4 + 1);
    scanlines[rowOffset] = 0; // Filter None
    buffer.copy(scanlines, rowOffset + 1, y * width * 4, (y + 1) * width * 4);
  }

  const compressedData = zlib.deflateSync(scanlines);

  // PNG Signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR chunk
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(width, 0);
  ihdrData.writeUInt32BE(height, 4);
  ihdrData[8] = 8; // Bit depth: 8
  ihdrData[9] = 6; // Color type: 6 (RGBA)
  ihdrData[10] = 0; // Compression method
  ihdrData[11] = 0; // Filter method
  ihdrData[12] = 0; // Interlace method
  const ihdrChunk = createChunk('IHDR', ihdrData);

  // IDAT chunk
  const idatChunk = createChunk('IDAT', compressedData);

  // IEND chunk
  const iendChunk = createChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

function crc32(buf) {
  let table = [];
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ table[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function createChunk(type, data) {
  const len = data.length;
  const typeBuf = Buffer.from(type, 'ascii');
  const chunk = Buffer.alloc(4 + 4 + len + 4);
  chunk.writeUInt32BE(len, 0);
  typeBuf.copy(chunk, 4);
  data.copy(chunk, 8);
  const crc = crc32(Buffer.concat([typeBuf, data]));
  chunk.writeUInt32BE(crc, 8 + len);
  return chunk;
}

const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

[16, 32, 48, 128].forEach(size => {
  const pngBuf = createPng(size);
  fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), pngBuf);
  console.log(`Generated icon${size}.png (${pngBuf.length} bytes)`);
});
