#!/usr/bin/env sh
set -eu

preset="${1:-1.7b}"
model_dir="${MODEL_DIR:-./models}"

case "$preset" in
  135m)
    repo="HuggingFaceTB/SmolLM2-135M-Instruct-GGUF"
    file="smollm2-135m-instruct-q4_k_m.gguf"
    ;;
  360m)
    repo="HuggingFaceTB/SmolLM2-360M-Instruct-GGUF"
    file="smollm2-360m-instruct-q4_k_m.gguf"
    ;;
  1.7b)
    repo="HuggingFaceTB/SmolLM2-1.7B-Instruct-GGUF"
    file="smollm2-1.7b-instruct-q4_k_m.gguf"
    ;;
  *)
    echo "Usage: $0 {135m|360m|1.7b}" >&2
    exit 2
    ;;
esac

mkdir -p "$model_dir"
target="$model_dir/$file"
if [ -e "$target" ]; then
  echo "Refusing to overwrite existing file: $target" >&2
  exit 1
fi

url="https://huggingface.co/$repo/resolve/main/$file"
headers="$(curl -fsSIL "$url")"
expected="$(printf '%s\n' "$headers" | sed -n 's/^[Xx]-[Ll]inked-[Ee]tag: *//p' | tail -n 1 | tr -d '"\r')"
case "$expected" in
  sha256:*) expected="${expected#sha256:}" ;;
esac
if ! printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  echo "The model host did not provide a SHA-256 LFS checksum; download aborted." >&2
  exit 1
fi

tmp="$(mktemp "$model_dir/.${file}.XXXXXX")"
trap 'rm -f "$tmp"' EXIT INT TERM
echo "Downloading $repo/$file"
curl -fL --retry 3 --progress-bar "$url" -o "$tmp"
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$tmp" | awk '{print $1}')"
else
  actual="$(shasum -a 256 "$tmp" | awk '{print $1}')"
fi
if [ "$actual" != "$expected" ]; then
  echo "Checksum mismatch: expected $expected, got $actual" >&2
  exit 1
fi
chmod 0444 "$tmp"
mv "$tmp" "$target"
trap - EXIT INT TERM
echo "Verified and saved $target"

