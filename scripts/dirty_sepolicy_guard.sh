#!/usr/bin/env bash
set -euo pipefail

guard_log() {
  printf '[ABK dirty-sepolicy] %s\n' "$*"
}

guard_warn() {
  printf '[ABK dirty-sepolicy][warn] %s\n' "$*" >&2
}

guard_die() {
  printf '[ABK dirty-sepolicy][error] %s\n' "$*" >&2
  exit 1
}

STRICT="${ABK_DIRTY_SEPOLICY_STRICT:-1}"
MODE="${ABK_DIRTY_SEPOLICY_MODE:-cleanup}"
MODULE_DIR="${DIRTY_SEPOLICY_MODULE_DIR:-}"

if [ -n "$MODULE_DIR" ] && [ -d "$MODULE_DIR" ]; then
  MODULE_DIR="$(cd "$MODULE_DIR" && pwd -P)"
fi

declare -a SCAN_ROOTS=()
declare -a CANDIDATE_FILES=()
declare -a MODIFIED_FILES=()
declare -a REMAINING_MATCHES=()

canonical_dir() {
  local path="$1"
  [ -n "$path" ] || return 1
  [ -d "$path" ] || return 1
  (cd "$path" && pwd -P)
}

add_scan_root() {
  local path="$1"
  local resolved existing
  local -a kept_roots=()

  resolved="$(canonical_dir "$path" 2>/dev/null || true)"
  [ -n "$resolved" ] || return 0

  for existing in "${SCAN_ROOTS[@]}"; do
    if path_is_under "$resolved" "$existing"; then
      return 0
    fi

    if path_is_under "$existing" "$resolved"; then
      continue
    fi

    kept_roots+=("$existing")
  done

  SCAN_ROOTS=("${kept_roots[@]}")
  SCAN_ROOTS+=("$resolved")
}

discover_scan_roots() {
  if [ -n "${KERNEL_ROOT:-}" ]; then
    add_scan_root "$KERNEL_ROOT"
  fi

  add_scan_root "${SUSFS4KSU:-}"
  add_scan_root "${KERNEL_PATCHES:-}"
  add_scan_root "${SUKISU_PATCHES:-}"

  if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    add_scan_root "${GITHUB_WORKSPACE:-}"
  fi
}

path_is_under() {
  local path="$1"
  local root="$2"

  [ -n "$root" ] || return 1
  [ "$path" = "$root" ] && return 0
  case "$path" in
    "$root"/*) return 0 ;;
    *) return 1 ;;
  esac
}

is_patch_file() {
  local file="$1"

  case "$file" in
    *.patch|*.diff) return 0 ;;
    *) return 1 ;;
  esac
}

is_candidate_file() {
  local file="$1"
  local lower

  lower="$(printf '%s' "$file" | tr 'A-Z' 'a-z')"

  case "$lower" in
    *.te|*.cil|*.conf|*.policy|*.rules|*.rule|*.sepolicy|*.patch|*.diff)
      return 0
      ;;
  esac

  case "$lower" in
    *selinux*|*sepolicy*|*policy*|*kernelsu*|*sukisu*|*resukisu*|*magisk*|*lsposed*|*susfs*)
      case "$lower" in
        *.c|*.h|*.cc|*.cpp|*.inc|*.sh|*.py|*.mk|*makefile|*.bp|*.bzl)
          return 0
          ;;
      esac
      ;;
  esac

  return 1
}

add_candidate_file() {
  local file="$1"
  local existing

  for existing in "${CANDIDATE_FILES[@]}"; do
    [ "$existing" = "$file" ] && return 0
  done

  CANDIDATE_FILES+=("$file")
}

skip_file() {
  local file="$1"
  local lower

  if [ -n "$MODULE_DIR" ] && path_is_under "$file" "$MODULE_DIR"; then
    return 0
  fi

  lower="$(printf '%s' "$file" | tr 'A-Z' 'a-z')"

  case "$lower" in
    */.git/*|*/.repo/*|*/out/*|*/bazel-*/*|*/build/*|*/dist/*|*/target/*|*/.gradle/*|*/node_modules/*)
      return 0
      ;;
    *.o|*.ko|*.a|*.so|*.dylib|*.dll|*.class|*.dex|*.jar|*.apk|*.zip|*.gz|*.xz|*.zst|*.bz2|*.7z|*.tar|*.img|*.bin|*.png|*.jpg|*.jpeg|*.webp|*.mp4|*.xcf)
      return 0
      ;;
  esac

  is_candidate_file "$file" || return 0
  return 1
}

file_is_text() {
  local file="$1"
  grep -Iq . "$file"
}

dirty_policy_awk='
function has_token(line, token, pattern) {
  pattern = "(^|[^[:alnum:]_])" token "([^[:alnum:]_]|$)"
  return line ~ pattern
}

function has_any(line, words, count, i) {
  for (i = 1; i <= count; i++) {
    if (has_token(line, words[i])) {
      return 1
    }
  }
  return 0
}

function normalize_line(raw, line) {
  line = raw
  sub(/\r$/, "", line)
  sub(/^[[:space:]]+/, "", line)
  sub(/[[:space:]]+$/, "", line)
  return line
}

function starts_policy_rule(raw, line, lower) {
  line = normalize_line(raw)
  lower = tolower(line)

  if (line == "" || lower ~ /^(#|\/\/|\*)/) {
    return 0
  }

  if (lower ~ /^allow([[:space:]]|\()/ ||
      lower ~ /^\(allow[[:space:]]/ ||
      lower ~ /(^|[^[:alnum:]_])allow([[:space:]]|\()/ ||
      lower ~ /(^|[^[:alnum:]_])(allow|ksu_allow|magiskpolicy)[[:space:]]*\(/) {
    return 1
  }

  return 0
}

function direct_rule_category(raw, line, lower, has_untrusted, has_binder, has_call) {
  line = normalize_line(raw)
  lower = tolower(line)

  if (!starts_policy_rule(line)) {
    return ""
  }

  split("magisk magiskd magisk_file magisk_exec magisk_log magisk_tmpfs", magisk_words, " ")
  split("ksu kernelsu sukisu resukisu ksu_file kernelsu_file kernelsu_app", ksu_words, " ")

  has_untrusted = lower ~ /(^|[^[:alnum:]_])untrusted_app[[:alnum:]_]*([^[:alnum:]_]|$)/
  has_binder = has_token(lower, "binder")
  has_call = has_token(lower, "call")

  if (has_token(lower, "system_server") && has_token(lower, "process") && has_token(lower, "execmem")) {
    return "system_server_execmem"
  }

  if (has_untrusted && has_binder && has_call && has_any(lower, magisk_words, 6)) {
    return "untrusted_app_magisk_binder_call"
  }

  if (has_untrusted && has_binder && has_call && has_any(lower, ksu_words, 7)) {
    return "untrusted_app_ksu_binder_call"
  }

  if (has_untrusted && has_token(lower, "lsposed_file") && has_token(lower, "file") &&
      (has_token(lower, "read") || has_token(lower, "open") || has_token(lower, "getattr") ||
       has_token(lower, "map") || has_token(lower, "ioctl") || has_token(lower, "lock"))) {
    return "untrusted_app_lsposed_file_read"
  }

  return ""
}

function statement_finished(line, lower) {
  lower = tolower(line)
  if (line ~ /;[[:space:]]*$/ ||
      line ~ /\)[[:space:]]*;?[[:space:]]*$/ ||
      lower ~ /^\}[[:space:]]*;?[[:space:]]*$/) {
    return 1
  }

  return 0
}

function compact_context(text) {
  gsub(/[[:space:]]+/, " ", text)
  sub(/^[[:space:]]+/, "", text)
  sub(/[[:space:]]+$/, "", text)
  return substr(text, 1, 500)
}

function has_policy_helper(lower) {
  if (lower ~ /(^|[^[:alnum:]_])(allow|ksu_allow)[[:space:]]*\(/ ||
      lower ~ /(^|[^[:alnum:]_])magiskpolicy([^[:alnum:]_]|$)/ ||
      lower ~ /(^|[^[:alnum:]_])allow_domain[[:space:]]*\(/ ||
      lower ~ /(^|[^[:alnum:]_])security_load_policy([^[:alnum:]_]|$)/ ||
      lower ~ /(^|[^[:alnum:]_])selinux_android_load_policy([^[:alnum:]_]|$)/ ||
      lower ~ /(^|[^[:alnum:]_])load_policy([^[:alnum:]_]|$)/ ||
      lower ~ /(^|[^[:alnum:]_])policydb[[:alnum:]_]*([^[:alnum:]_]|$)/ ||
      lower ~ /(^|[^[:alnum:]_])avtab[[:alnum:]_]*([^[:alnum:]_]|$)/) {
    return 1
  }

  return 0
}

function audit_context_category(raw, lower, has_untrusted, has_binder, has_call, has_file_read) {
  lower = tolower(raw)

  if (!has_policy_helper(lower)) {
    return ""
  }

  has_untrusted = lower ~ /(^|[^[:alnum:]_])untrusted_app[[:alnum:]_]*([^[:alnum:]_]|$)/
  has_binder = has_token(lower, "binder")
  has_call = has_token(lower, "call")
  has_file_read = 0
  if (has_token(lower, "read") || has_token(lower, "open") || has_token(lower, "getattr") ||
      has_token(lower, "map") || has_token(lower, "ioctl") || has_token(lower, "lock")) {
    has_file_read = 1
  }

  if (has_token(lower, "system_server") && has_token(lower, "execmem")) {
    return "runtime_system_server_execmem_policy_source"
  }

  if (has_untrusted && has_binder && has_call &&
      (has_token(lower, "magisk") || has_token(lower, "magiskd") || has_token(lower, "magisk_file"))) {
    return "runtime_untrusted_app_magisk_binder_policy_source"
  }

  if (has_untrusted && has_binder && has_call &&
      (has_token(lower, "ksu") || has_token(lower, "kernelsu") ||
       has_token(lower, "sukisu") || has_token(lower, "resukisu"))) {
    return "runtime_untrusted_app_ksu_binder_policy_source"
  }

  if (has_untrusted && has_token(lower, "lsposed_file") && has_file_read) {
    return "runtime_untrusted_app_lsposed_file_policy_source"
  }

  return ""
}
'

clean_plain_file() {
  local file="$1"
  local tmp
  tmp="$(mktemp)"

  if awk "$dirty_policy_awk"'
    {
      category = direct_rule_category($0)
      if (category != "") {
        changed = 1
        printf "%s:%d:%s:%s\n", FILENAME, FNR, category, $0 > "/dev/stderr"
        next
      }
      print
    }
    END { exit changed ? 2 : 0 }
  ' "$file" > "$tmp" 2>"$tmp.log"; then
    rm -f "$tmp" "$tmp.log"
    return 0
  else
    local status="$?"
    if [ "$status" -eq 2 ]; then
      cat "$tmp" > "$file"
      while IFS= read -r line; do
        guard_log "removed $line"
      done < "$tmp.log"
      rm -f "$tmp" "$tmp.log"
      MODIFIED_FILES+=("$file")
      return 0
    fi
    cat "$tmp.log" >&2 || true
    rm -f "$tmp" "$tmp.log"
    guard_die "failed to clean $file"
  fi
}

clean_patch_file() {
  local file="$1"
  local tmp
  tmp="$(mktemp)"

  if awk "$dirty_policy_awk"'
    function parse_header(line, m) {
      return match(line, /^@@ -([0-9]+)(,([0-9]+))? \+([0-9]+)(,([0-9]+))? @@(.*)$/, m)
    }

    function count_line(line) {
      if (line ~ /^ /) {
        old_count++
        new_count++
      } else if (line ~ /^-/ && line !~ /^---/) {
        old_count++
      } else if (line ~ /^\+/ && line !~ /^\+\+\+/) {
        new_count++
      }
    }

    function format_range(start, count) {
      if (count == 1) {
        return start
      }
      return start "," count
    }

    function flush_hunk(i) {
      if (!in_hunk) {
        return
      }

      print "@@ -" format_range(old_start, old_count) " +" format_range(new_start, new_count) " @@" hunk_suffix
      for (i = 1; i <= hunk_len; i++) {
        print hunk[i]
      }

      delete hunk
      hunk_len = 0
      in_hunk = 0
      old_count = 0
      new_count = 0
    }

    {
      if (parse_header($0, m)) {
        flush_hunk()
        in_hunk = 1
        old_start = m[1]
        new_start = m[4]
        hunk_suffix = m[7]
        next
      }

      if (in_hunk) {
        if ($0 ~ /^\+/ && $0 !~ /^\+\+\+/) {
          candidate = substr($0, 2)
          category = direct_rule_category(candidate)
          if (category != "") {
            changed = 1
            printf "%s:%d:%s:%s\n", FILENAME, FNR, category, $0 > "/dev/stderr"
            next
          }
        }

        count_line($0)
        hunk[++hunk_len] = $0
        next
      }

      print
    }

    END {
      flush_hunk()
      exit changed ? 2 : 0
    }
  ' "$file" > "$tmp" 2>"$tmp.log"; then
    rm -f "$tmp" "$tmp.log"
    return 0
  else
    local status="$?"
    if [ "$status" -eq 2 ]; then
      cat "$tmp" > "$file"
      while IFS= read -r line; do
        guard_log "removed patch addition $line"
      done < "$tmp.log"
      rm -f "$tmp" "$tmp.log"
      MODIFIED_FILES+=("$file")
      return 0
    fi
    cat "$tmp.log" >&2 || true
    rm -f "$tmp" "$tmp.log"
    guard_die "failed to clean patch $file"
  fi
}

scan_remaining_file() {
  local file="$1"
  local matches

  if is_patch_file "$file"; then
    matches="$(
      awk "$dirty_policy_awk"'
        function flush_statement() {
          if (collecting) {
            category = direct_rule_category(statement)
            if (category != "") {
              printf "%s:%d:%s:multiline:%s\n", FILENAME, statement_line, category, statement
            }
            collecting = 0
            statement = ""
            statement_line = 0
          }
        }

        /^\+/ && $0 !~ /^\+\+\+/ {
          candidate = substr($0, 2)
          category = direct_rule_category(candidate)
          if (category != "") {
            printf "%s:%d:%s:%s\n", FILENAME, FNR, category, $0
          }

          if (collecting) {
            statement = statement " " candidate
            if (statement_finished(candidate)) {
              flush_statement()
            }
          } else if (starts_policy_rule(candidate) && category == "" && !statement_finished(candidate)) {
            collecting = 1
            statement = candidate
            statement_line = FNR
          }

          next
        }

        { flush_statement() }

        END {
          flush_statement()
        }
      ' "$file"
    )"
  else
    matches="$(
      awk "$dirty_policy_awk"'
        function flush_statement() {
          if (collecting) {
            category = direct_rule_category(statement)
            if (category != "") {
              printf "%s:%d:%s:multiline:%s\n", FILENAME, statement_line, category, statement
            }
            collecting = 0
            statement = ""
            statement_line = 0
          }
        }

        {
          category = direct_rule_category($0)
          if (category != "") {
            printf "%s:%d:%s:%s\n", FILENAME, FNR, category, $0
          }

          if (collecting) {
            statement = statement " " $0
            if (statement_finished($0)) {
              flush_statement()
            }
          } else if (starts_policy_rule($0) && category == "" && !statement_finished($0)) {
            collecting = 1
            statement = $0
            statement_line = FNR
          }
        }

        END {
          flush_statement()
        }
      ' "$file"
    )"
  fi

  if [ -n "$matches" ]; then
    while IFS= read -r line; do
      REMAINING_MATCHES+=("$line")
    done <<< "$matches"
  fi
}

scan_suspicious_file() {
  local file="$1"
  local matches

  if is_patch_file "$file"; then
    matches="$(
      awk "$dirty_policy_awk"'
        function push_window(line, number, i) {
          for (i = 1; i < 8; i++) {
            window[i] = window[i + 1]
            numbers[i] = numbers[i + 1]
          }
          window[8] = line
          numbers[8] = number
        }

        function joined_window(i, out, first) {
          first = 0
          out = ""
          for (i = 1; i <= 8; i++) {
            if (window[i] != "") {
              if (!first) {
                first = numbers[i]
              }
              out = out " " window[i]
            }
          }
          window_start = first ? first : FNR
          return out
        }

        /^\+/ && $0 !~ /^\+\+\+/ {
          candidate = substr($0, 2)
          push_window(candidate, FNR)
          context = joined_window()
          category = audit_context_category(context)
          if (category != "") {
            key = category ":" compact_context(context)
            if (!seen[key]++) {
              printf "%s:%d:%s:context:%s\n", FILENAME, window_start, category, compact_context(context)
            }
          }
        }

        $0 !~ /^\+/ || $0 ~ /^\+\+\+/ {
          delete window
          delete numbers
        }
      ' "$file"
    )"
  else
    matches="$(
      awk "$dirty_policy_awk"'
        function push_window(line, number, i) {
          for (i = 1; i < 8; i++) {
            window[i] = window[i + 1]
            numbers[i] = numbers[i + 1]
          }
          window[8] = line
          numbers[8] = number
        }

        function joined_window(i, out, first) {
          first = 0
          out = ""
          for (i = 1; i <= 8; i++) {
            if (window[i] != "") {
              if (!first) {
                first = numbers[i]
              }
              out = out " " window[i]
            }
          }
          window_start = first ? first : FNR
          return out
        }

        {
          push_window($0, FNR)
          context = joined_window()
          category = audit_context_category(context)
          if (category != "") {
            key = category ":" compact_context(context)
            if (!seen[key]++) {
              printf "%s:%d:%s:context:%s\n", FILENAME, window_start, category, compact_context(context)
            }
          }
        }
      ' "$file"
    )"
  fi

  if [ -n "$matches" ]; then
    while IFS= read -r line; do
      REMAINING_MATCHES+=("$line")
    done <<< "$matches"
  fi
}

for_each_candidate_file() {
  local callback="$1"
  local file

  for file in "${CANDIDATE_FILES[@]}"; do
    "$callback" "$file"
  done
}

collect_candidate_files() {
  local root file before after added

  for root in "${SCAN_ROOTS[@]}"; do
    before="${#CANDIDATE_FILES[@]}"
    guard_log "scanning root: $root"

    while IFS= read -r -d '' file; do
      skip_file "$file" && continue
      file_is_text "$file" || continue
      add_candidate_file "$file"
    done < <(
      find "$root" \
        \( -type d \( \
          -name .git -o \
          -name .repo -o \
          -name out -o \
          -name build -o \
          -name dist -o \
          -name target -o \
          -name .gradle -o \
          -name node_modules -o \
          -name 'bazel-*' \
        \) -prune \) -o \
        \( -type f \( \
          -iname '*.te' -o \
          -iname '*.cil' -o \
          -iname '*.conf' -o \
          -iname '*.policy' -o \
          -iname '*.rules' -o \
          -iname '*.rule' -o \
          -iname '*.sepolicy' -o \
          -iname '*.patch' -o \
          -iname '*.diff' -o \
          \( \
            \( -ipath '*selinux*' -o \
               -ipath '*sepolicy*' -o \
               -ipath '*policy*' -o \
               -ipath '*kernelsu*' -o \
               -ipath '*sukisu*' -o \
               -ipath '*resukisu*' -o \
               -ipath '*magisk*' -o \
               -ipath '*lsposed*' -o \
               -ipath '*susfs*' \
            \) -a \( \
              -iname '*.c' -o \
              -iname '*.h' -o \
              -iname '*.cc' -o \
              -iname '*.cpp' -o \
              -iname '*.inc' -o \
              -iname '*.sh' -o \
              -iname '*.py' -o \
              -iname '*.mk' -o \
              -iname 'makefile' -o \
              -iname '*.bp' -o \
              -iname '*.bzl' \
            \) \
          \) \
        \) -print0 \)
    )

    after="${#CANDIDATE_FILES[@]}"
    added=$((after - before))
    guard_log "root candidates: $added"
  done
}

clean_candidate() {
  local file="$1"

  if is_patch_file "$file"; then
    clean_patch_file "$file"
  else
    clean_plain_file "$file"
  fi
}

main() {
  case "$MODE" in
    cleanup|audit) ;;
    *) guard_die "unsupported ABK_DIRTY_SEPOLICY_MODE: $MODE" ;;
  esac

  discover_scan_roots

  if [ "${#SCAN_ROOTS[@]}" -eq 0 ]; then
    guard_warn "no scan roots found"
    return 0
  fi

  guard_log "scan roots:"
  printf '  %s\n' "${SCAN_ROOTS[@]}"

  collect_candidate_files
  guard_log "total unique candidates: ${#CANDIDATE_FILES[@]}"

  guard_log "mode: $MODE"

  if [ "$MODE" = "cleanup" ]; then
    for_each_candidate_file clean_candidate
  fi

  for_each_candidate_file scan_remaining_file

  if [ "$MODE" = "audit" ]; then
    for_each_candidate_file scan_suspicious_file
  fi

  if [ "${#MODIFIED_FILES[@]}" -eq 0 ]; then
    if [ "$MODE" = "cleanup" ]; then
      guard_log "no dirty SELinux policy grants needed cleanup"
    else
      guard_log "audit mode did not modify files"
    fi
  else
    guard_log "modified files:"
    printf '  %s\n' "${MODIFIED_FILES[@]}"
  fi

  if [ "${#REMAINING_MATCHES[@]}" -gt 0 ]; then
    guard_warn "targeted dirty SELinux policy grants remain:"
    printf '  %s\n' "${REMAINING_MATCHES[@]}" >&2

    if [ "$STRICT" = "1" ]; then
      guard_die "strict mode blocked the build because dirty SELinux grants remain"
    fi

    guard_warn "strict mode disabled; continuing despite remaining matches"
  fi

  guard_log "done"
}

main "$@"
