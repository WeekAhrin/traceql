#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p \
  "$SCRIPT_DIR/malapi" \
  "$SCRIPT_DIR/sigma" \
  "$SCRIPT_DIR/elastic" \
  "$SCRIPT_DIR/lolbas"

echo "[1/4] Updating MalAPI dataset..."
curl -fsSL "https://raw.githubusercontent.com/BlackSnufkin/LitterBox/main/Utils/malapi.json" -o "$TMP_DIR/malapi.json"
if command -v python3 >/dev/null 2>&1; then
  python3 -m json.tool "$TMP_DIR/malapi.json" > "$SCRIPT_DIR/malapi/malapi.json"
else
  cp "$TMP_DIR/malapi.json" "$SCRIPT_DIR/malapi/malapi.json"
fi

echo "[2/4] Updating LOLBAS dataset..."
curl -fsSL "https://lolbas-project.github.io/api/lolbas.json" -o "$SCRIPT_DIR/lolbas/lolbas.json"

echo "[3/4] Updating SigmaHQ rules..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git "$TMP_DIR/sigma-hq" >/dev/null 2>&1
(
  cd "$TMP_DIR/sigma-hq"
  git sparse-checkout set rules/linux rules/windows/process_creation >/dev/null 2>&1
)
SIGMA_RULES=(
  "rules/linux/builtin/lnx_ldso_preload_injection.yml"
  "rules/linux/builtin/lnx_potential_susp_ebpf_activity.yml"
  "rules/linux/builtin/lnx_shell_susp_rev_shells.yml"
  "rules/linux/builtin/lnx_shell_susp_commands.yml"
  "rules/linux/builtin/lnx_shell_clear_cmd_history.yml"
  "rules/linux/auditd/lnx_auditd_disable_aslr_protection.yml"
  "rules/linux/auditd/lnx_auditd_keylogging_with_pam_d.yml"
  "rules/linux/auditd/lnx_auditd_susp_c2_commands.yml"
  "rules/linux/process_creation/proc_creation_lnx_curl_wget_exec_tmp.yml"
  "rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml"
  "rules/linux/process_creation/proc_creation_lnx_python_reverse_shell.yml"
  "rules/linux/process_creation/proc_creation_lnx_python_base64_encoded_execution.yml"
  "rules/linux/process_creation/proc_creation_lnx_base64_execution.yml"
  "rules/linux/process_creation/proc_creation_lnx_auditctl_clear_rules.yml"
  "rules/linux/process_creation/proc_creation_lnx_bpf_kprob_tracing_enabled.yml"
  "rules/linux/process_creation/proc_creation_lnx_cap_setuid.yml"
  "rules/windows/process_creation/proc_creation_win_susp_abusing_debug_privilege.yml"
  "rules/windows/process_creation/proc_creation_win_susp_alternate_data_streams.yml"
  "rules/windows/process_creation/proc_creation_win_susp_cli_obfuscation_escape_char.yml"
  "rules/windows/process_creation/proc_creation_win_susp_copy_system_dir_lolbin.yml"
  "rules/windows/process_creation/proc_creation_win_susp_data_exfiltration_via_cli.yml"
  "rules/windows/process_creation/proc_creation_win_susp_add_user_local_admin_group.yml"
)
for rel in "${SIGMA_RULES[@]}"; do
  cp "$TMP_DIR/sigma-hq/$rel" "$SCRIPT_DIR/sigma/"
done

echo "[4/4] Updating Elastic protections-artifacts rules..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/elastic/protections-artifacts.git "$TMP_DIR/elastic-pa" >/dev/null 2>&1
(
  cd "$TMP_DIR/elastic-pa"
  git sparse-checkout set behavior/rules >/dev/null 2>&1
)
ELASTIC_RULES=(
  "behavior/rules/linux/credential_access_potential_credential_access_via_ptrace.toml"
  "behavior/rules/linux/credential_access_potential_linux_credential_dumping_via_proc_filesystem.toml"
  "behavior/rules/linux/defense_evasion_creation_of_hidden_shared_object_file.toml"
  "behavior/rules/linux/defense_evasion_decoded_payload_piped_to_interpreter.toml"
  "behavior/rules/linux/defense_evasion_execution_of_memory_file_descriptor_via_suspicious_process.toml"
  "behavior/rules/linux/defense_evasion_egress_network_connection_from_memory_file_descriptor.toml"
  "behavior/rules/linux/defense_evasion_attempt_to_disable_selinux.toml"
  "behavior/rules/linux/defense_evasion_attempt_to_disable_auditd_service.toml"
  "behavior/rules/linux/command_and_control_egress_network_connection_followed_by_command_execution.toml"
  "behavior/rules/linux/command_and_control_python_network_connection_followed_by_command_execution.toml"
  "behavior/rules/windows/collection_keystroke_messages_hooking_via_setwindowshookex.toml"
  "behavior/rules/windows/collection_keystroke_input_capture_via_registerrawinputdevices.toml"
  "behavior/rules/windows/credential_access_lsass_memory_dump_via_minidumpwritedump.toml"
  "behavior/rules/windows/credential_access_lsass_access_attempt_from_unbacked_memory.toml"
  "behavior/rules/windows/command_and_control_ingress_tool_transfer_via_powershell.toml"
  "behavior/rules/windows/command_and_control_ingress_tool_transfer_via_curl.toml"
  "behavior/rules/cross-platform/collection_environment_variable_secret_collection.toml"
  "behavior/rules/cross-platform/credential_access_potential_credential_harvesting_via_python.toml"
  "behavior/rules/cross-platform/defense_evasion_tampering_of_bash_command_line_history.toml"
  "behavior/rules/cross-platform/execution_kill_command_executed_from_binary_in_unusual_location.toml"
)
for rel in "${ELASTIC_RULES[@]}"; do
  cp "$TMP_DIR/elastic-pa/$rel" "$SCRIPT_DIR/elastic/"
done

echo "Done. Dataset summary:"
du -sh "$SCRIPT_DIR"/{malapi,sigma,elastic,lolbas}
