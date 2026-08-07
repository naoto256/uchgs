//! Ignored acceptance-test skeletons enumerating every item in SPEC §16.
//!
//! Each skeleton records the normative SPEC section(s) that later phases must
//! implement. This scaffold contains no product behavior.

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
acceptance_skeleton!(
    extract_01_rejects_malformed_git_objects,
    "未知の型・壊れた長さ・重複必須ヘッダ・順序違いtree entryを拒否する",
    "SPEC §3.3"
);
acceptance_skeleton!(
    extract_02_omits_git_plumbing_fields,
    "treeのmode/object ID/枠組みとcommitの親/tree/時刻/枠組みを判定対象にしない",
    "SPEC §3.0–§3.1, §3.3"
);
acceptance_skeleton!(
    extract_03_supports_sha1_and_sha256_object_formats,
    "sha1とsha256の両object formatで成立する",
    "SPEC §2.2, §3.3"
);
acceptance_skeleton!(
    extract_04_has_exactly_five_unit_kinds,
    "種類はfile/path/commit/tag/refの5つだけ",
    "SPEC §2.2, §3"
);
acceptance_skeleton!(
    extract_05_reproduces_all_appendix_a_vectors,
    "付録Aの全golden vectorの長さとSHA-256を再現する",
    "SPEC Appendix A, §3"
);
acceptance_skeleton!(
    extract_06_commit_omits_parent_time_and_framing,
    "commit抜き出しから親・時刻・枠組みを落とす",
    "SPEC §3.1, Appendix A.1"
);
acceptance_skeleton!(
    extract_07_commit_omits_all_extra_headers,
    "gpgsigやencoding等の追加ヘッダをcommit抜き出しに含めない",
    "SPEC §3.1, Appendix A.2"
);
acceptance_skeleton!(
    extract_08_signed_commit_rebase_preserves_key,
    "署名付きcommitをrebaseしてもcommitの鍵が変わらない",
    "SPEC §3.1, Appendix A.2, Appendix A.7"
);
acceptance_skeleton!(
    extract_09_adding_signature_preserves_key,
    "未署名commitに後から署名を足してもcommitの鍵が変わらない",
    "SPEC §3.1, Appendix A.2"
);
acceptance_skeleton!(
    extract_10_mergetag_yields_only_commit_unit,
    "mergetag付きmerge commitからcommit判定対象だけを1つ出す",
    "SPEC §3.1, Appendix A.3b"
);
acceptance_skeleton!(
    extract_11_rewrite_operations_preserve_commit_key,
    "rebase・cherry-pick・amendの前後でcommitの鍵が変わらない",
    "SPEC §3.1, Appendix A.7"
);
acceptance_skeleton!(
    extract_12_duplicate_file_content_deduplicates_file_not_path,
    "同内容が2箇所ならfileは1つでpathは2つになる",
    "SPEC §3.3 step 4"
);
acceptance_skeleton!(
    extract_13_rename_changes_only_path,
    "内容を変えず移動するとpathだけが新しくなる",
    "SPEC §3.3 step 3"
);
acceptance_skeleton!(
    extract_14_submodule_and_symlink_semantics,
    "submoduleはpathのみでsymlinkはリンク先文字列がfileになる",
    "SPEC §3.0, §3.3"
);
acceptance_skeleton!(
    extract_15_rejects_invalid_git_timestamps,
    "Git文法外の時刻・タイムゾーンを持つobjectを拒否する",
    "SPEC §3.1–§3.2, §3.3"
);

// SPEC §16「鍵」; normative rules: SPEC §2.2, §3, §6.3.
acceptance_skeleton!(
    key_01_kind_separates_identical_bytes,
    "同じバイト列でも種類が違えば別の鍵になる",
    "SPEC §2.2, §3"
);
acceptance_skeleton!(
    key_02_git_object_id_does_not_satisfy_judgment,
    "Git object IDは判定を満たさない",
    "SPEC §2.2, §3"
);
acceptance_skeleton!(
    key_03_state_key_uses_canonical_tree_bytes,
    "状態判定の鍵はtree正準バイト列のSHA-256でtree OIDは観測位置だけ",
    "SPEC §3.0, §6.3"
);

// SPEC §16「承認の自己完結」; normative rules: SPEC §7.3–§7.4, §8, §9.3.
acceptance_skeleton!(
    self_contained_01_delegation_embeds_grant_chain_and_credential,
    "委任承認のdelegationにgrant request・人間のapproval・公開鍵を同梱する",
    "SPEC §7.3, §9.3"
);
acceptance_skeleton!(
    self_contained_02_verifies_after_daemon_exit,
    "daemon終了後も承認バイト列と登録簿だけで検証できる",
    "SPEC §7.3–§7.4, §9.3"
);
acceptance_skeleton!(
    self_contained_03_has_no_persistent_grants_store,
    "権限材料をディスクに保管するgrantsディレクトリが存在しない",
    "SPEC §9.1–§9.5"
);
acceptance_skeleton!(
    self_contained_04_rejects_unregistered_grant_signer,
    "grant_approval署名者が登録簿に無ければ拒否する",
    "SPEC §7.4, §8, §9.3"
);
acceptance_skeleton!(
    self_contained_05_direct_approval_has_null_delegation,
    "直接承認ではdelegationがnullになる",
    "SPEC §7.3"
);

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

// SPEC §16「承認」; normative rules: SPEC §7.
acceptance_skeleton!(
    approval_01_caller_cannot_supply_nonce_or_time,
    "nonceと時刻を呼び出し側から与えられない",
    "SPEC §7.1, §7.3, §12.3"
);
acceptance_skeleton!(
    approval_02_repeated_content_gets_distinct_request_ids,
    "同内容の再実行でも別request IDになる",
    "SPEC §7.1"
);
acceptance_skeleton!(
    approval_03_expired_digest_cannot_be_recreated,
    "時効requestと同digestのrequestを二度と作れない",
    "SPEC §7.5"
);
acceptance_skeleton!(
    approval_04_verifies_exact_persisted_request_bytes,
    "承認を保存requestのexact bytesに対して検証する",
    "SPEC §7.4"
);
acceptance_skeleton!(
    approval_05_one_scope_request_contains_whole_required_set,
    "1観点の要求集合を1requestにまとめる",
    "SPEC §7.1, §10.1, §11.3"
);
acceptance_skeleton!(
    approval_06_finalized_pair_moves_to_approvals,
    "判定確定後にrequestとapprovalの対をapprovalsへ移す",
    "SPEC §7.6"
);
acceptance_skeleton!(
    approval_07_crashed_move_is_reconciled_by_next_gate,
    "移動中crash後に次gateで対を最終化する",
    "SPEC §7.6"
);

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
acceptance_skeleton!(
    registry_03_documents_match_closed_schema,
    "credential・genesis・enrollmentが§8.4の欄と完全一致する",
    "SPEC §8.4"
);
acceptance_skeleton!(
    registry_04_recomputes_all_document_ids_on_load,
    "credential ID・genesis ID・enrollment_idを読込ごとに再計算する",
    "SPEC §8.4"
);
acceptance_skeleton!(
    registry_05_signature_material_matches_credential_type,
    "signature materialとcredential typeの組合せ違いを拒否する",
    "SPEC §7.4, §8.4"
);
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

// SPEC §16「承認者の制限」; normative rules: SPEC §7.2, §9.3.
acceptance_skeleton!(
    delegated_restriction_01_rejects_direct_only_actions,
    "委任鍵によるdelegation-grant・policy-update・signer-enrollをdaemonと検証側で拒否する",
    "SPEC §7.2, §9.3"
);

// SPEC §16「delegate」; normative rules: SPEC §9.
acceptance_skeleton!(
    delegate_01_ttl_is_half_open,
    "delegate有効期間は終端を含まない半開区間",
    "SPEC §9.1, §9.3"
);
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
    delegate_06_rejects_non_judgment_requests,
    "判定以外のrequestを拒否する",
    "SPEC §7.2, §9.3"
);
acceptance_skeleton!(
    delegate_07_approval_verifies_after_authority_expires,
    "委任承認は自己完結し権限消滅後も検証できる",
    "SPEC §7.3–§7.4, §9.3, §9.5"
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
