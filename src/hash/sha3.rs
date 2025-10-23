use crate::hash::Hasher;

const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const RHO: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[derive(Clone)]
pub struct Sha3 {
    state: [u64; 25],
    buffer: Vec<u8>,
    rate: usize,
}

impl Sha3 {
    pub fn new() -> Self {
        Sha3 {
            state: [0; 25],
            buffer: Vec::with_capacity(136),
            rate: 136,
        }
    }

    fn _keccakf(&mut self) {
        for rnd in 0..24 {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.state[x] ^ self.state[5 + x] ^ self.state[10 + x] ^ self.state[15 + x] ^ self.state[20 + x];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for y in 0..5 {
                for x in 0..5 {
                    self.state[5 * y + x] ^= d[x];
                }
            }

            let mut b = [0u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    let idx = 5 * y + x;
                    let rot = RHO[y][x];
                    b[5 * ((2 * x + 3 * y) % 5) + y] = self.state[idx].rotate_left(rot);
                }
            }
            self.state = b;

            let mask = u64::MAX;
            for y in 0..5 {
                let row = &self.state[5 * y..5 * y + 5];
                let mut new_row = [0u64; 5];
                for x in 0..5 {
                    new_row[x] = row[x] ^ ((mask ^ row[(x + 1) % 5]) & row[(x + 2) % 5]);
                }
                for x in 0..5 {
                    self.state[5 * y + x] = new_row[x];
                }
            }

            self.state[0] ^= RC[rnd];
        }
    }
}

impl Hasher for Sha3 {
    fn update(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
        while self.buffer.len() >= self.rate {
            let block: [u8; 136] = self.buffer[0..self.rate].try_into().unwrap();
            for i in 0..(self.rate / 8) {
                let val = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
                self.state[i] ^= val;
            }
            self._keccakf();
            self.buffer.drain(0..self.rate);
        }
    }

    fn finalize(&mut self) -> String {
        self.buffer.push(0x06);
        self.buffer.resize(self.rate - 1, 0);
        self.buffer.push(0x80);
        let block: [u8; 136] = self.buffer.as_slice().try_into().unwrap();
        for i in 0..(self.rate / 8) {
            let val = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
            self.state[i] ^= val;
        }
        self._keccakf();
        self.buffer.clear();
        let mut digest = Vec::with_capacity(32);
        for i in 0..4 {
            digest.extend_from_slice(&self.state[i].to_le_bytes());
        }
        digest.iter().map(|&b| format!("{:02x}", b)).collect()
    }
}