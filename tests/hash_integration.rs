use CryptoMal::hash::{Hasher, Sha256, Sha3};
#[test]
fn test_sha256_vectors() {
    let tests: Vec<(&[u8], &str)> = vec![
        (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    ];
    for (input, expected) in tests {
        let mut h = Sha256::new();
        h.update(input);
        assert_eq!(h.finalize(), expected);
    }
}

#[test]
fn test_sha3_vectors() {
    let tests: Vec<(&[u8], &str)> = vec![
        (b"", "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"),
        (b"abc", "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376"),
        (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18"),
    ];
    for (input, expected) in tests {
        let mut h = Sha3::new();
        h.update(input);
        assert_eq!(h.finalize(), expected);
    }
}
#[test]
fn test_avalanche_effect() {
    let original = b"Hello, world!";
    let modified = b"Hello, world?";

    let mut h = Sha256::new();
    h.update(original);
    let hash1 = h.finalize();

    let mut h = Sha256::new();
    h.update(modified);
    let hash2 = h.finalize();

    let bin1 = u256_from_hex(&hash1);
    let bin2 = u256_from_hex(&hash2);
    let diff_count = bin1
        .iter()
        .zip(bin2.iter())
        .map(|(&b1, &b2)| (b1 ^ b2).count_ones() as usize)
        .sum::<usize>();

    assert!(100 < diff_count && diff_count < 156, "Avalanche effect weak: {} bits changed", diff_count);
}

fn u256_from_hex(hex: &str) -> [u8; 32] {
    let bytes = hex::decode(hex).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}