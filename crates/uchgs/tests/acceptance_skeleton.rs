//! Acceptance tests enumerating every item in SPEC §16.
//!
//! Extractor-only items are executable; later-phase items remain ignored
//! skeletons. Every item records its normative SPEC section(s).

use uchgs::extract::{JudgmentUnit, ObjectFormat, UnitKind, extract_git_object};

/// Builds exact Git object framing for extractor-only SPEC §3.3 acceptance tests.
fn frame(kind: &str, body: &[u8]) -> Vec<u8> {
    let mut object = format!("{kind} {}\0", body.len()).into_bytes();
    object.extend_from_slice(body);
    object
}

/// Extracts the sole unit expected from a valid commit/tag/blob object.
fn extract_one(format: ObjectFormat, kind: &str, body: &[u8]) -> JudgmentUnit {
    let units = extract_git_object(format, &frame(kind, body)).expect("valid SPEC §3 object");
    assert_eq!(units.len(), 1, "object must yield one unit");
    units.into_iter().next().expect("one unit")
}

macro_rules! acceptance_skeleton {
    ($name:ident, $item:literal, $sections:literal) => {
        #[doc = concat!("SPEC §16 item: ", $item)]
        #[doc = concat!(" Normative source: ", $sections, ".")]
        #[test]
        #[ignore = "SPEC §16 skeleton; implementation is not present yet"]
        fn $name() {
            let _provenance = ($item, $sections);
            todo!("acceptance behavior is implemented in a later phase")
        }
    };
}

// SPEC §16「path の集合差」; normative rules: SPEC §3.3, §10.1, §11.3.
acceptance_skeleton!(
    path_01_content_only_change_requires_only_file,
    "中身だけ変わったファイルの path は要求されず file だけが要求される",
    "SPEC §3.3, §10.1, §11.3"
);
acceptance_skeleton!(
    path_02_rename_without_content_change_requires_only_path,
    "中身を変えず移動したファイルは path だけが要求される",
    "SPEC §3.3, §10.1, §11.3"
);
acceptance_skeleton!(
    path_03_published_path_is_not_required,
    "公開済みの path は要求されない",
    "SPEC §10.1, §11.2–§11.3"
);
acceptance_skeleton!(
    path_04_empty_file_can_be_judged_and_recorded,
    "空ファイルを file として判定・記録できる",
    "SPEC §3.3, §6.2"
);

// SPEC §16「project」; normative rules: SPEC §5.2, §5.5, §6.2–§6.3.
acceptance_skeleton!(
    project_01_policy_update_rejects_project_change,
    "候補 config の project が現 ACTIVE と違えば policy 更新が失敗する",
    "SPEC §5.2, §5.5"
);
acceptance_skeleton!(
    project_02_judgment_records_have_no_project_field,
    "判定の記録に project 欄が無い",
    "SPEC §6.2–§6.3"
);

// SPEC §16「auditor」; normative rules: SPEC §6, §7, §8, §12.
acceptance_skeleton!(
    auditor_01_request_and_cli_have_no_auditor_field,
    "要求に auditor 欄が無く CLI に --auditor が無い",
    "SPEC §7.1, §12.1"
);
acceptance_skeleton!(
    auditor_02_approval_and_records_omit_principal_and_auditor,
    "承認に principal 欄が無く判定記録に auditor 欄が無い",
    "SPEC §6.2–§6.3, §7.3"
);
acceptance_skeleton!(
    auditor_03_signer_identity_follows_credential_and_delegation,
    "署名者は credential_id から一意に特定でき委任なら delegation で登録済み鍵まで辿れる",
    "SPEC §4, §7.3–§7.4, §8, §9.3"
);

// SPEC §16「bootstrap」; normative rules: SPEC §8.2, §12.1, §12.4.
acceptance_skeleton!(
    bootstrap_01_requires_key_and_principal,
    "--key と --principal が無ければ失敗する",
    "SPEC §8.2, §12.1"
);
acceptance_skeleton!(
    bootstrap_02_does_not_use_unsigned_defaults,
    "unsigned config の既定値を暗黙に使わない",
    "SPEC §8.2, §12.4"
);

// SPEC §16「判定対象の抜き出し」; normative rules: SPEC §2–§3, §10–§11, Appendix A.
/// SPEC §16「未知型・壊れた長さ・重複必須ヘッダ・tree順序違反」; SPEC §3.3.
#[test]
fn extract_01_rejects_malformed_git_objects() {
    assert!(extract_git_object(ObjectFormat::Sha1, b"note 0\0").is_err());
    assert!(extract_git_object(ObjectFormat::Sha1, b"blob 01\0x").is_err());
    assert!(extract_git_object(ObjectFormat::Sha1, b"blob 2\0x").is_err());

    let duplicate_tree = b"tree 0000000000000000000000000000000000000000\n\
tree 1111111111111111111111111111111111111111\n\
author A <a@x> 1 +0000\n\
committer A <a@x> 1 +0000\n\
\n\
message\n";
    assert!(extract_git_object(ObjectFormat::Sha1, &frame("commit", duplicate_tree)).is_err());

    let oid = [1_u8; 20];
    let mut reversed_tree = b"100644 z\0".to_vec();
    reversed_tree.extend_from_slice(&oid);
    reversed_tree.extend_from_slice(b"100644 a\0");
    reversed_tree.extend_from_slice(&oid);
    assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &reversed_tree)).is_err());

    let mut dotdot_tree = b"100644 ..\0".to_vec();
    dotdot_tree.extend_from_slice(&oid);
    assert!(extract_git_object(ObjectFormat::Sha1, &frame("tree", &dotdot_tree)).is_err());
}

/// SPEC §16「Git配管を判定対象にしない」; SPEC §3.0–§3.1, §3.3.
#[test]
fn extract_02_omits_git_plumbing_fields() {
    let before = b"tree 0000000000000000000000000000000000000000\n\
parent 1111111111111111111111111111111111111111\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 -0500\n\
\n\
message\n";
    let after = b"tree ffffffffffffffffffffffffffffffffffffffff\n\
parent eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n\
author A <a@x> 300 +0900\n\
committer C <c@x> 400 +0000\n\
\n\
message\n";
    let before = extract_one(ObjectFormat::Sha1, "commit", before);
    let after = extract_one(ObjectFormat::Sha1, "commit", after);
    assert_eq!(before.bytes(), after.bytes());
    assert_eq!(before.id(), after.id());
}

/// SPEC §16「sha1/sha256 object format」; SPEC §2.2, §3.3.
#[test]
fn extract_03_supports_sha1_and_sha256_object_formats() {
    for (format, oid_length) in [(ObjectFormat::Sha1, 20), (ObjectFormat::Sha256, 32)] {
        let mut tree = b"100644 file\0".to_vec();
        tree.extend(std::iter::repeat_n(1, oid_length));
        assert!(extract_git_object(format, &frame("tree", &tree)).is_ok());
    }

    let sha1 = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer A <a@x> 1 +0000\n\
\n\
message\n";
    let sha256 = b"tree 0000000000000000000000000000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer A <a@x> 1 +0000\n\
\n\
message\n";
    assert_eq!(
        extract_one(ObjectFormat::Sha1, "commit", sha1).bytes(),
        extract_one(ObjectFormat::Sha256, "commit", sha256).bytes(),
    );
}

/// SPEC §16「unit kindは閉じた5種」; SPEC §2.2, §3.
#[test]
fn extract_04_has_exactly_five_unit_kinds() {
    assert_eq!(
        [
            UnitKind::File,
            UnitKind::Path,
            UnitKind::Commit,
            UnitKind::Tag,
            UnitKind::Ref,
        ]
        .map(UnitKind::as_str),
        ["file", "path", "commit", "tag", "ref"],
    );
    assert!("tree".parse::<UnitKind>().is_err());
}
acceptance_skeleton!(
    extract_05_reproduces_all_appendix_a_vectors,
    "付録Aの全golden vectorの長さとSHA-256を再現する",
    "SPEC Appendix A, §3"
);
/// SPEC §16「commitは親・時刻・枠組みを落とす」; SPEC §3.1, Appendix A.1.
#[test]
fn extract_06_commit_omits_parent_time_and_framing() {
    let body = b"tree 0000000000000000000000000000000000000000\n\
parent 1111111111111111111111111111111111111111\n\
author A <a@x> -1 +0900\n\
committer C <c@x> 2 -0500\n\
\n\
message\n";
    let unit = extract_one(ObjectFormat::Sha1, "commit", body);
    assert_eq!(
        unit.bytes(),
        b"author A <a@x>\ncommitter C <c@x>\n\nmessage\n"
    );
}

/// SPEC §16「commit追加ヘッダを全部落とす」; SPEC §3.1, Appendix A.2.
#[test]
fn extract_07_commit_omits_all_extra_headers() {
    let plain = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
\n\
message\n";
    let extended = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
encoding ISO-8859-1\n\
gpgsig signature\n\
\x20continuation\n\
\n\
message\n";
    assert_eq!(
        extract_one(ObjectFormat::Sha1, "commit", plain).id(),
        extract_one(ObjectFormat::Sha1, "commit", extended).id(),
    );
}
acceptance_skeleton!(
    extract_08_signed_commit_rebase_preserves_key,
    "署名付きcommitをrebaseしてもcommitの鍵が変わらない",
    "SPEC §3.1, Appendix A.2, Appendix A.7"
);
/// SPEC §16「後付け署名でcommit鍵不変」; SPEC §3.1, Appendix A.2.
#[test]
fn extract_09_adding_signature_preserves_key() {
    let plain = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
\n\
signed later\n";
    let signed = b"tree 0000000000000000000000000000000000000000\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
gpgsig signature\n\
\x20continued\n\
\n\
signed later\n";
    assert_eq!(
        extract_one(ObjectFormat::Sha1, "commit", plain).id(),
        extract_one(ObjectFormat::Sha1, "commit", signed).id(),
    );
}

/// SPEC §16「mergetagはcommit unit 1つだけ」; SPEC §3.1, Appendix A.3b.
#[test]
fn extract_10_mergetag_yields_only_commit_unit() {
    let body = b"tree 0000000000000000000000000000000000000000\n\
parent 1111111111111111111111111111111111111111\n\
author A <a@x> 1 +0000\n\
committer C <c@x> 2 +0000\n\
mergetag object 1111111111111111111111111111111111111111\n\
\x20type commit\n\
\x20tag v1\n\
\x20tagger T <t@x> 3 +0000\n\
\x20\n\
\x20tag message\n\
\n\
merge message\n";
    let units = extract_git_object(ObjectFormat::Sha1, &frame("commit", body))
        .expect("valid mergetag commit");
    assert_eq!(units.len(), 1);
    assert_eq!(units[0].kind(), UnitKind::Commit);
    assert_eq!(
        units[0].bytes(),
        b"author A <a@x>\ncommitter C <c@x>\n\nmerge message\n"
    );
}
acceptance_skeleton!(
    extract_11_rewrite_operations_preserve_commit_key,
    "rebase・cherry-pick・amendの前後でcommitの鍵が変わらない",
    "SPEC §3.1, Appendix A.7"
);
/// SPEC §16「同内容2箇所はfile 1つ/path 2つ」; SPEC §3 and §4.
#[test]
fn extract_12_duplicate_file_content_deduplicates_file_not_path() {
    let first_file = JudgmentUnit::file(b"same contents".to_vec());
    let second_file = JudgmentUnit::file(b"same contents".to_vec());
    let first_path = JudgmentUnit::path(b"first/name".to_vec()).expect("valid first path");
    let second_path = JudgmentUnit::path(b"second/name".to_vec()).expect("valid second path");

    assert_eq!(first_file.id(), second_file.id());
    assert_ne!(first_path.id(), second_path.id());
}

/// SPEC §16「内容不変の移動はpathだけが新しい」; SPEC §3 and §4.
#[test]
fn extract_13_rename_changes_only_path() {
    let before_file = JudgmentUnit::file(b"unchanged".to_vec());
    let after_file = JudgmentUnit::file(b"unchanged".to_vec());
    let before_path = JudgmentUnit::path(b"old/name".to_vec()).expect("valid old path");
    let after_path = JudgmentUnit::path(b"new/name".to_vec()).expect("valid new path");

    assert_eq!(before_file.id(), after_file.id());
    assert_ne!(before_path.id(), after_path.id());
}
acceptance_skeleton!(
    extract_14_submodule_and_symlink_semantics,
    "submoduleはpathのみでsymlinkはリンク先文字列がfileになる",
    "SPEC §3.0, §3.3"
);
/// SPEC §16「Git文法外の時刻・timezoneを拒否」; SPEC §3.1–§3.3.
#[test]
fn extract_15_rejects_invalid_git_timestamps() {
    for identity in [
        "A <a@x> 01 +0000",
        "A <a@x> 1 0000",
        "A <a@x> 1 +000",
        "A <a@x> x +0000",
    ] {
        let body = format!(
            "tree 0000000000000000000000000000000000000000\nauthor {identity}\ncommitter A <a@x> 1 +0000\n\nmessage\n"
        );
        assert!(extract_git_object(ObjectFormat::Sha1, &frame("commit", body.as_bytes())).is_err());
    }
}

/// SPEC §16「non-UTF-8 identityはA.8の鍵を再現」; SPEC §3.1, Appendix A.8.
#[test]
fn extract_16_non_utf8_identity_reproduces_appendix_a8_key() {
    let body = b"tree da462c9f8a2be3504f3f50d77c36a6066b02d876\n\
author Ren\xe9 Dubois <rene@example.com> 1700000000 +0900\n\
committer Ren\xe9 Dubois <rene@example.com> 1700000123 -0500\n\
\n\
fix encoding\n";
    let unit = extract_one(ObjectFormat::Sha1, "commit", body);
    assert_eq!(unit.bytes().len(), 93);
    assert_eq!(
        unit.digest().to_string(),
        "3bdc2f5072b618cede691d92d8a955438b0f61c494fba34277e2e6f879d4585e"
    );
}
acceptance_skeleton!(
    extract_17_commit_gate_accepts_non_utf8_author_identity,
    "git var GIT_AUTHOR_IDENTの出力がUTF-8でなくてもcommit gateが動く",
    "SPEC §3.1, §10.4, Appendix A.8"
);

// SPEC §16「鍵」; normative rules: SPEC §2.2, §3, §6.3.
/// SPEC §16「同じbytesでも種類が違えば別鍵」; SPEC §2.2, §3–§4.
#[test]
fn key_01_kind_separates_identical_bytes() {
    let file = JudgmentUnit::file(b"same".to_vec());
    let path = JudgmentUnit::path(b"same".to_vec()).expect("valid path");
    assert_eq!(file.digest(), path.digest());
    assert_ne!(file.id(), path.id());
}
acceptance_skeleton!(
    key_02_git_object_id_does_not_satisfy_judgment,
    "Git object IDは判定を満たさない",
    "SPEC §2.2, §3"
);
// key_03 は authority_acceptance.rs で解禁済み。

// SPEC §16「承認の自己完結」は authority_acceptance.rs で解禁済み。

// SPEC §16「commit gate」; normative rules: SPEC §10.
acceptance_skeleton!(
    commit_gate_01_requires_only_units_absent_from_head,
    "HEADに無い単位だけを要求する",
    "SPEC §10.1"
);
acceptance_skeleton!(
    commit_gate_02_unborn_repo_requires_full_tree,
    "HEADが無いrepoではtree全体のfileとpathを要求する",
    "SPEC §10.1"
);
acceptance_skeleton!(
    commit_gate_03_deletion_only_requires_new_commit,
    "削除だけのcommitでも新しいcommitを要求し消えたfile/pathは要求しない",
    "SPEC §10.3–§10.4"
);
acceptance_skeleton!(
    commit_gate_04_commit_msg_reads_all_bytes_without_rewrite,
    "commit-msgはコメントを含む全バイトを見てファイルを書き換えない",
    "SPEC §10.2"
);
acceptance_skeleton!(
    commit_gate_05_cleanup_changed_message_is_required_at_push,
    "cleanupで変わったmessageはpush gateで再要求する",
    "SPEC §10.2, §11.3"
);
acceptance_skeleton!(
    commit_gate_06_already_judged_units_are_not_required,
    "判定済み単位を再要求せず同じcommitの2回目は空になる",
    "SPEC §10.1"
);

// SPEC §16「push gate」; normative rules: SPEC §11.
acceptance_skeleton!(
    push_gate_01_excludes_all_published_origin_tips,
    "originの全tipにある公開済みobjectを除外する",
    "SPEC §11.2–§11.3"
);
acceptance_skeleton!(
    push_gate_02_new_branch_excludes_shared_history,
    "新branchのpushでも共有履歴を要求しない",
    "SPEC §11.2–§11.3"
);
acceptance_skeleton!(
    push_gate_03_missing_local_origin_tip_increases_target,
    "ローカルに無いorigin tipは除外せず対象が増える",
    "SPEC §11.2–§11.3"
);
acceptance_skeleton!(
    push_gate_04_ls_remote_failure_fails_gate,
    "ls-remote失敗時にgateも失敗する",
    "SPEC §11.2"
);
acceptance_skeleton!(
    push_gate_05_delete_update_has_no_target,
    "削除updateは対象を生まない",
    "SPEC §11.3"
);
acceptance_skeleton!(
    push_gate_06_paths_use_all_target_commit_root_trees,
    "path新側は対象全commit root tree和集合で途中追加後削除の名前も要求する",
    "SPEC §10.1 step 3, §11.3"
);
acceptance_skeleton!(
    push_gate_07_direct_tree_publication_yields_paths,
    "direct tree refとtag対象treeはpathを要求しdirect blob refはfileだけ",
    "SPEC §10.1 step 3, §11.3"
);
acceptance_skeleton!(
    push_gate_08_missing_shallow_or_partial_objects_fail_with_recovery,
    "欠落object・shallow・partialは具体的復旧手順付きで失敗する",
    "SPEC §11.3"
);
acceptance_skeleton!(
    push_gate_09_rejects_url_instead_of_remote_name,
    "remote名ではなくURLを渡すpushを拒否する",
    "SPEC §11.1"
);
acceptance_skeleton!(
    push_gate_10_push_intent_omits_connection_url,
    "PushIntentに接続先URLを保存しない",
    "SPEC §11.1"
);
acceptance_skeleton!(
    push_gate_11_state_scope_ignores_ref_namespace,
    "状態観点がrefの名前空間で絞られない",
    "SPEC §5.3, §11.4"
);

// SPEC §16「承認」7項目は authority_acceptance.rs で解禁済み。

// SPEC §16「設定」; normative rules: SPEC §5.
acceptance_skeleton!(
    policy_01_config_has_only_scope_name_type_and_gate_requirements,
    "設定には観点名・型・gate要求だけがあり対象選択欄が無い",
    "SPEC §5.2–§5.4"
);
acceptance_skeleton!(
    policy_02_active_mismatch_fails,
    "期待ACTIVEとの不一致を拒否する",
    "SPEC §5.5"
);
acceptance_skeleton!(
    policy_03_old_bundle_is_removed_after_activation,
    "有効化直後に古いbundleを消す",
    "SPEC §5.5"
);
acceptance_skeleton!(
    policy_04_old_judgments_survive_policy_change,
    "policy変更後も過去判定を有効とする",
    "SPEC §5.5, §6"
);

// SPEC §16「鍵の登録」; normative rules: SPEC §8.
acceptance_skeleton!(
    registry_01_genesis_can_approve_later_enrollment,
    "genesis鍵は最初のpolicy承認後も登録を承認できる",
    "SPEC §8.2–§8.3"
);
acceptance_skeleton!(
    registry_02_unregistered_signer_cannot_enroll,
    "未登録鍵による登録を拒否する",
    "SPEC §8.3"
);
// registry_03–05 は authority_acceptance.rs で解禁済み。
acceptance_skeleton!(
    registry_06_plaintext_private_keys_are_unsupported,
    "平文秘密鍵を生成せず受け付けない",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_07_passphrase_uses_only_controlling_terminal,
    "passphraseをstdin・環境・引数から受けず制御端末だけで読む",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_08_empty_passphrase_is_rejected,
    "空passphraseを拒否する",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_09_envelope_public_tamper_breaks_decryption,
    "封筒公開部の改変で復号を失敗させる",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_10_wrong_passphrase_fails_decryption,
    "誤passphraseで復号を失敗させる",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_11_seed_public_key_must_match_credential,
    "seed由来公開鍵と封筒credentialの不一致を拒否する",
    "SPEC §8.6"
);
acceptance_skeleton!(
    registry_12_openssh_private_keys_are_unsupported,
    "OpenSSH形式の鍵を受け付けない",
    "SPEC §8.6"
);

// SPEC §16「policy の同一性」; normative rules: SPEC §5.5.
acceptance_skeleton!(
    policy_identity_01_active_directory_and_request_digest_match,
    "ACTIVE digest・bundle名・SHA-256(request.json)が一致する",
    "SPEC §5.5"
);
acceptance_skeleton!(
    policy_identity_02_config_id_matches_config_digest,
    "request config_id不一致をpolicy-invalidにする",
    "SPEC §5.5"
);
acceptance_skeleton!(
    policy_identity_03_any_bundle_substitution_fails,
    "bundleの3点いずれの差替えも読込失敗にする",
    "SPEC §5.5"
);

// SPEC §16「delegate」; normative rules: SPEC §9.
acceptance_skeleton!(
    delegate_02_binary_derives_interval_from_ttl,
    "--ttlから期間をバイナリが算出する",
    "SPEC §9.1, §12.1"
);
acceptance_skeleton!(
    delegate_03_exits_on_expiry,
    "期限切れでdaemonが自発終了する",
    "SPEC §9.2"
);
acceptance_skeleton!(
    delegate_04_zeroizes_key_on_sigint_and_sigterm,
    "SIGINT・SIGTERMで鍵をゼロ埋めして終了する",
    "SPEC §9.2"
);
acceptance_skeleton!(
    delegate_05_has_no_stop_channel,
    "停止用socket・pipe・control fileが存在しない",
    "SPEC §9.2, §12.1"
);
acceptance_skeleton!(
    delegate_07_approval_verifies_after_authority_expires,
    "委任承認は自己完結し権限消滅後も検証できる",
    "SPEC §7.3–§7.4, §9.3, §9.5"
);

// SPEC §16「失敗の出し方」; normative rules: SPEC §13.2, §15.
acceptance_skeleton!(
    failure_01_all_failures_follow_classification_and_output_contract,
    "どの失敗も§15の分類を持ち§13.2の出力契約を満たす",
    "SPEC §13.2, §15"
);
acceptance_skeleton!(
    failure_02_runtime_errors_are_mapped_without_raw_output,
    "panicを含む想定外の実行時エラーも生出力を見せず最上位で分類へ写像する",
    "SPEC §13.2, §15"
);
acceptance_skeleton!(
    failure_03_classification_uses_internal_types_not_display_text,
    "失敗分類は内部型で決まり表示文字列の一致では決まらない",
    "SPEC §15"
);

// SPEC §16「存在しないこと」; normative closed surfaces: SPEC §6–§7, §9, §12.
acceptance_skeleton!(
    absence_01_retired_verbs_records_and_schemas_do_not_exist,
    "baseline・revoke・delegation stopの動詞・記録・schemaが存在しない",
    "SPEC §6, §7.2, §9, §12.1"
);
acceptance_skeleton!(
    absence_02_state_judgment_has_no_delta_field,
    "状態判定に差分欄が存在しない",
    "SPEC §6.3"
);
acceptance_skeleton!(
    absence_03_delegation_has_no_use_limit,
    "delegate権限に回数上限欄が存在しない",
    "SPEC §7.3, §9.1"
);
acceptance_skeleton!(
    absence_04_no_recipient_held_delegation,
    "受取側が鍵を持つdelegate型・欄・引数が存在しない",
    "SPEC §7.3, §9, §12.1"
);
acceptance_skeleton!(
    absence_05_no_repository_genesis,
    "repo単位genesisが存在しない",
    "SPEC §8.1–§8.2"
);
acceptance_skeleton!(
    absence_06_no_retired_signature_scheme,
    "引退した署名方式の痕跡が存在しない",
    "SPEC §4, §7.3, §8.4"
);
acceptance_skeleton!(
    absence_07_no_exec_scope_shell_or_failure_class,
    "exec型の観点・shell起動・exec-failed分類が存在しない",
    "SPEC §5.2–§5.4, §11.4, §15"
);
acceptance_skeleton!(
    absence_08_no_run_field_argument_or_cli_verb,
    "判定をまとめるrunの欄・引数・CLI動詞が存在しない",
    "SPEC §6–§7, §12.1"
);
acceptance_skeleton!(
    absence_09_policy_has_no_recall_field,
    "設定に説明文や表示用テキストのrecall欄が存在しない",
    "SPEC §5.2–§5.4"
);
