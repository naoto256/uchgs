//! Red-first golden-vector tests transcribed from SPEC Appendix A.
//!
//! The test-local API is intentionally temporary. The extractor remains
//! deliberately unimplemented until SPEC §3 is implemented.

#[derive(Clone, Copy)]
enum UnitKind {
    File,
    Path,
    Commit,
    Tag,
    Ref,
}

struct ExtractedUnit {
    bytes: Vec<u8>,
    sha256: String,
}

/// Provisional red stub for the extraction and unit digest rules in SPEC §2.2 and §3.
fn extract_and_hash(_kind: UnitKind, _input: &[u8]) -> ExtractedUnit {
    todo!("SPEC §3 extraction is implemented in a later phase")
}

fn assert_golden(
    kind: UnitKind,
    input: &[u8],
    expected_bytes: &[u8],
    expected_length: usize,
    expected_sha256: &str,
) {
    assert_eq!(
        expected_bytes.len(),
        expected_length,
        "SPEC Appendix A expected-byte length",
    );
    let actual = extract_and_hash(kind, input);
    assert_eq!(actual.bytes, expected_bytes);
    assert_eq!(actual.bytes.len(), expected_length);
    assert_eq!(actual.sha256, expected_sha256);
}

/// SPEC Appendix A.1; extraction rule: SPEC §3.1.
#[test]
fn a1_commit_basic() {
    const INPUT: &[u8] = b"tree da462c9f8a2be3504f3f50d77c36a6066b02d876\n\
author Alice  Smith <alice@example.com> 1700000000 +0900\n\
committer Alice  Smith <alice@example.com> 1700000123 -0500\n\
\n\
fix typo\n\
\n\
body line\n";
    const EXPECTED: &[u8] = b"author Alice  Smith <alice@example.com>\n\
committer Alice  Smith <alice@example.com>\n\
\n\
fix typo\n\
\n\
body line\n";

    assert_eq!(INPUT.len(), 184, "SPEC Appendix A.7 records A.1 raw length");

    assert_golden(
        UnitKind::Commit,
        INPUT,
        EXPECTED,
        104,
        "1ea5ffb1268a2514ce841a20c6c19c106f274e95857ef9498d126a1f8afea48b",
    );
}

/// SPEC Appendix A.2; extraction rule: SPEC §3.1.
#[test]
fn a2_commit_drops_gpgsig_and_continuations() {
    const INPUT: &[u8] = b"tree da462c9f8a2be3504f3f50d77c36a6066b02d876\n\
parent 5e0c637988f3fcf856ea6cd33a0697f92389031f\n\
author Alice  Smith <alice@example.com> 1700000300 +0900\n\
committer Alice  Smith <alice@example.com> 1700000400 +0000\n\
gpgsig -----BEGIN PGP SIGNATURE-----\n\
 \n\
 iQEzBAABCgAd\n\
 -----END PGP SIGNATURE-----\n\
\n\
signed commit\n";
    const EXPECTED: &[u8] = b"author Alice  Smith <alice@example.com>\n\
committer Alice  Smith <alice@example.com>\n\
\n\
signed commit\n";

    assert_golden(
        UnitKind::Commit,
        INPUT,
        EXPECTED,
        98,
        "3683d7052698c1d3c5dcde2fdc009a3f2deaa263e9c83aaa1c443dada4ddb6e3",
    );
}

/// SPEC Appendix A.3; extraction rule: SPEC §3.2.
#[test]
fn a3_annotated_tag() {
    const INPUT: &[u8] = b"object 5e0c637988f3fcf856ea6cd33a0697f92389031f\n\
type commit\n\
tag v1.0\n\
tagger Alice  Smith <alice@example.com> 1700000200 +0000\n\
\n\
release one\n";
    const EXPECTED: &[u8] = b"tag v1.0\n\
tagger Alice  Smith <alice@example.com>\n\
\n\
release one\n";

    assert_golden(
        UnitKind::Tag,
        INPUT,
        EXPECTED,
        62,
        "c955101a3c2ae9742456a3ba3a903c15a50d52dab803f990e6aa155fdd3cc432",
    );
}

/// SPEC Appendix A.3b; extraction rule: SPEC §3.1.
#[test]
fn a3b_mergetag_commit_produces_only_commit_unit() {
    const INPUT: &[u8] = b"tree da462c9f8a2be3504f3f50d77c36a6066b02d876\n\
parent 5e0c637988f3fcf856ea6cd33a0697f92389031f\n\
parent 158729fe5df289a2706f178b015605ddf882f836\n\
author Alice  Smith <alice@example.com> 1700000500 +0900\n\
committer Alice  Smith <alice@example.com> 1700000600 +0000\n\
mergetag object 5e0c637988f3fcf856ea6cd33a0697f92389031f\n\
 type commit\n\
 tag v1.0\n\
 tagger Alice  Smith <alice@example.com> 1700000200 +0000\n\
 \n\
 release one\n\
\n\
Merge tag 'v1.0'\n";
    const EXPECTED: &[u8] = b"author Alice  Smith <alice@example.com>\n\
committer Alice  Smith <alice@example.com>\n\
\n\
Merge tag 'v1.0'\n";

    assert_golden(
        UnitKind::Commit,
        INPUT,
        EXPECTED,
        101,
        "93073b2c316407336b3d3558381f2266155ca76bb9d760a26a74fe77bf0e9a0e",
    );
}

/// SPEC Appendix A.4; extraction rule: SPEC §3.3 step 2 (`blob`).
#[test]
fn a4_file_contents() {
    const CASES: &[(&[u8], usize, &str)] = &[
        (
            b"hello\n",
            6,
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
        ),
        (
            b"fn main() {}\n",
            13,
            "536e506bb90914c243a12b397b9a998f85ae2cbd9ba02dfd03a9e155ca5ca0f4",
        ),
    ];

    for &(input, length, _) in CASES {
        assert_eq!(input.len(), length, "SPEC Appendix A.4 input length");
    }
    for &(input, length, sha256) in CASES {
        assert_golden(UnitKind::File, input, input, length, sha256);
    }
}

/// SPEC Appendix A.5; extraction rule: SPEC §3.0 and §3.3 step 3.
#[test]
fn a5_paths() {
    const CASES: &[(&[u8], usize, &str)] = &[
        (
            b"README.md",
            9,
            "b335630551682c19a781afebcf4d07bf978fb1f8ac04c6bf87428ed5106870f5",
        ),
        (
            b"src",
            3,
            "25a6634263c1b1f6fc4697a04e2b9904ea4b042a89af59dc93ec1f5d44848a26",
        ),
        (
            b"src/deep",
            8,
            "2bec29cd31be6f31ac9f7fb5bc2b22f07c1f6fca5cae9281aa1ff5b3b964ed3c",
        ),
        (
            b"src/deep/main.rs",
            16,
            "1732ba105902d7c5b77175944d3da6332fbc484b3da47abe8a702eb6951a6915",
        ),
    ];

    for &(input, length, _) in CASES {
        assert_eq!(input.len(), length, "SPEC Appendix A.5 input length");
    }
    for &(input, length, sha256) in CASES {
        assert_golden(UnitKind::Path, input, input, length, sha256);
    }
}

/// SPEC Appendix A.6; extraction rule: SPEC §11.3 (`ref`).
#[test]
fn a6_refs() {
    const CASES: &[(&[u8], usize, &str)] = &[
        (
            b"refs/heads/main",
            15,
            "f921bd05e68b03740c450e565e0e6173e546193170b2dd404ddb6f153e9b5bf3",
        ),
        (
            b"refs/tags/v1.0",
            14,
            "9c00a1ce4a9c499fa4cd2f11fca0d82863bd9b3228ca4df2c63f657a32ba3787",
        ),
    ];

    for &(input, length, _) in CASES {
        assert_eq!(input.len(), length, "SPEC Appendix A.6 input length");
    }
    for &(input, length, sha256) in CASES {
        assert_golden(UnitKind::Ref, input, input, length, sha256);
    }
}

/// SPEC Appendix A.7; extraction rule: SPEC §3.1; invariance rationale: DESIGN_REQ §3–§4.
#[test]
fn a7_rebase_invariance() {
    const INPUT: &[u8] = b"tree da462c9f8a2be3504f3f50d77c36a6066b02d876\n\
parent 158729fe5df289a2706f178b015605ddf882f836\n\
author Alice  Smith <alice@example.com> 1700000000 +0900\n\
committer Alice  Smith <alice@example.com> 1700099999 +0000\n\
\n\
fix typo\n\
\n\
body line\n";
    const EXPECTED: &[u8] = b"author Alice  Smith <alice@example.com>\n\
committer Alice  Smith <alice@example.com>\n\
\n\
fix typo\n\
\n\
body line\n";

    assert_eq!(INPUT.len(), 232, "SPEC Appendix A.7 raw input length");
    assert_golden(
        UnitKind::Commit,
        INPUT,
        EXPECTED,
        104,
        "1ea5ffb1268a2514ce841a20c6c19c106f274e95857ef9498d126a1f8afea48b",
    );
}
