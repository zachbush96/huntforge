const encoder = new TextEncoder();
const crcTable = Array.from({ length: 256 }, (_, value) => {
  for (let bit = 0; bit < 8; bit += 1) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

function checksum(contents) {
  let crc = 0xffffffff;
  for (const value of contents) crc = crcTable[(crc ^ value) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

export function zip(files) {
  const entries = [];
  const directory = [];
  let offset = 0;
  let directorySize = 0;
  const write = (buffer, fields) => {
    const view = new DataView(buffer.buffer);
    for (const [position, value, size] of fields) {
      if (size === 4) view.setUint32(position, value, true);
      else view.setUint16(position, value, true);
    }
  };
  for (const [name, text] of Object.entries(files)) {
    const filename = encoder.encode(name);
    const data = encoder.encode(text);
    const crc = checksum(data);
    const local = new Uint8Array(30);
    const central = new Uint8Array(46);
    write(local, [[0, 0x04034b50, 4], [4, 20], [6, 0x800], [12, 33], [14, crc, 4],
      [18, data.length, 4], [22, data.length, 4], [26, filename.length]]);
    write(central, [[0, 0x02014b50, 4], [4, 20], [6, 20], [8, 0x800], [14, 33], [16, crc, 4],
      [20, data.length, 4], [24, data.length, 4], [28, filename.length], [42, offset, 4]]);
    entries.push(local, filename, data);
    directory.push(central, filename);
    offset += local.length + filename.length + data.length;
    directorySize += central.length + filename.length;
  }
  const end = new Uint8Array(22);
  const count = Object.keys(files).length;
  write(end, [[0, 0x06054b50, 4], [8, count], [10, count], [12, directorySize, 4], [16, offset, 4]]);
  return new Blob([...entries, ...directory, end], { type: "application/zip" });
}
