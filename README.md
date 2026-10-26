# RedactThis

RedactThis is a small, self-hosted safety layer for text you intend to paste into an external AI service. It replaces common secrets and identifiers with stable typed placeholders, asks a local SmolLM2 model to catch contextual misses, and then runs an independent verification pass before enabling copy.

Everything needed at runtime is served locally: one Go binary, one HTML page, one JavaScript file, and a private llama.cpp sidecar. There are no CDNs, analytics, accounts, or request storage.

> [!IMPORTANT]
> RedactThis reduces accidental disclosure; it cannot guarantee that every sensitive value will be detected. Review output before sharing it, particularly when using the 135M or 360M models or an unsupported custom GGUF.

## Quick start

Requirements are Docker Engine with Compose v2, `curl`, and roughly 1.2 GB of free space for the recommended quantized model.

```sh
./scripts/download-model.sh 1.7b
docker compose --env-file deploy/cpu.env up --build -d
```

Open <http://127.0.0.1:8080>. Follow logs with `docker compose --env-file deploy/cpu.env logs -f`, and stop the deployment with:

```sh
docker compose --env-file deploy/cpu.env down
```

The download script supports `135m`, `360m`, and `1.7b`. It downloads the official HuggingFaceTB Q4_K_M GGUF and compares the completed file with the SHA-256 value supplied by Hugging Face's LFS metadata. Existing files are never overwritten.

## How processing works

1. Built-in Go/RE2 detectors remove recognizable private keys, provider and segmented API keys, JWTs, credential assignments, sensitive URL parameters, serial/device identifiers, IP and MAC addresses, UUIDs, emails, phone numbers, street addresses, US ZIP codes, Canadian postal codes, and Luhn-valid payment card numbers.
2. The sanitized document is split at line boundaries. SmolLM2 returns schema-constrained JSON containing only exact residual sensitive substrings; application code, not the model, performs replacements.
3. A fresh prompt verifies the completed document. If it reports a possible miss, the page shows the partial draft and locations. It can be run through redaction again, or copied only after an explicit second-click warning.

Repeated values use the same placeholder throughout a request, such as `[EMAIL_1]`. Formatting and unrelated text are not intentionally rewritten. Oversized lines receive overlapping model windows so identifiers near a boundary remain visible.

The size selector controls total input and approximate per-model-call limits:

| Preset | Total characters | Chunk target | Intended use |
| --- | ---: | ---: | --- |
| Light | 25,000 | 4,000 | Lower memory and latency |
| Balanced | 100,000 | 6,000 | Stack traces, emails, and messages |
| Large | 250,000 | 8,000 | Very large pastes and longer jobs |

## GPU deployment

The application image never changes. Select a llama.cpp sidecar using the matching environment file, similar to GPU-enabled media-server containers:

```sh
# NVIDIA CUDA 12; requires NVIDIA Container Toolkit
docker compose --env-file deploy/nvidia.env up --build -d

# AMD ROCm; requires accessible /dev/kfd and /dev/dri devices
docker compose --env-file deploy/rocm.env up --build -d

# Intel SYCL/oneAPI; requires the Intel compute runtime and /dev/dri
docker compose --env-file deploy/intel.env up --build -d
```

The Compose file pins each official llama.cpp image to an immutable multi-platform digest. NVIDIA uses `gpus: all`; ROCm receives `/dev/kfd` and `/dev/dri`; Intel receives `/dev/dri`. Set `GPU_LAYERS` in the selected environment file if full offload is unsuitable.

Linux is the primary target. Under WSL2:

- CPU and NVIDIA CUDA work when Docker Desktop/Engine and NVIDIA's WSL driver integration are installed.
- AMD ROCm requires a GPU and Windows/WSL driver combination explicitly supported by AMD. `/dev/kfd` must exist inside the Linux environment.
- Intel SYCL requires working Intel GPU paravirtualization plus `/dev/dri`; support varies by Windows, WSL kernel, and GPU generation.

Check the selected backend with `docker compose --env-file deploy/nvidia.env logs llama-nvidia` (substitute the profile in use). If device pass-through is unavailable, use the CPU profile.

## Models and tuning

The recommended default is SmolLM2-1.7B-Instruct Q4_K_M. To use another downloaded preset, edit `MODEL_FILE` and `MODEL_NAME` in the selected file under `deploy/`.

To use a custom model, put its GGUF in `models/` and set those same variables to its filename and display name. A custom model must have a llama.cpp-compatible chat template and must reliably follow the structured response schema. Compatibility and redaction quality are not guaranteed.

Common optional variables can be appended to an environment file:

```dotenv
APP_PORT=8080
CONTEXT_SIZE=8192
GPU_LAYERS=99
MODEL_TIMEOUT=10m
```

Model selection and inference parameters are deploy-time settings; restart the Compose project after changing them. The app joins a normal edge network for its loopback-only published port and a separate internal network for llama.cpp; the llama.cpp API has no host port and remains unreachable directly from the host or LAN.

## Custom detection rules

Edit `config/rules.json` before starting the service. A custom expression uses Go's linear-time RE2 syntax and must contain a named `secret` capture so surrounding context remains untouched:

```json
{
  "disabledBuiltins": ["PHONE_NUMBER"],
  "rules": [
    {
      "name": "CUSTOMER_ID",
      "pattern": "customer[_-]?id\\s*[:=]\\s*(?P<secret>[A-Z]{3}-[0-9]{6})"
    }
  ]
}
```

Category names become uppercase typed placeholders. Invalid JSON, regular expressions, duplicate names, or missing `secret` captures make the application fail at startup. See `config/rules.example.json` for a copyable example.

Built-in detector names are `PRIVATE_KEY`, `API_KEY`, `JWT`, `CREDENTIAL`, `URL_SECRET`, `DEVICE_ID`, `EMAIL`, `STREET_ADDRESS`, `MAC_ADDRESS`, `UUID`, `IP_ADDRESS`, `CANADIAN_POSTAL_CODE`, `US_ZIP_CODE`, `PHONE_NUMBER`, and `PAYMENT_CARD`.

## HTTP interface

The browser uses two same-origin endpoints:

- `GET /api/status` reports model readiness, selected backend, and configured presets.
- `POST /api/redact` accepts `{"text":"...","sizePreset":"balanced"}`. It returns `200` with `status: "verified"`, or `422` with `status: "review_required"`, the draft, and finding offsets.

Model failures, invalid structured output after one retry, timeouts, and incomplete processing fail closed. API errors never return a result marked safe.

## Privacy and threat model

- Input, residual findings, and the value-to-placeholder map live only in request memory.
- The server does not log request bodies, prompts, model responses, or redacted output.
- The browser uses no local storage. All assets are embedded in the binary and protected by a restrictive Content Security Policy.
- Text still reaches the locally hosted model after deterministic secrets have been removed. It is never intentionally sent to an external inference API.
- The default listener is `127.0.0.1` through Docker and has no authentication. Do not change it to a LAN-facing binding without adding an authenticated reverse proxy and TLS.
- Model output is untrusted. JSON grammar constraints, exact-substring validation, and non-rewriting prompts limit prompt-injection impact, but model quality remains part of the safety boundary.
- Placeholder mappings are intentionally not exported, so v1 redaction is irreversible.

## Development

Go 1.23 or newer is required.

```sh
make test
make build
make compose-check
```

The unit suite covers deterministic detectors, custom rule validation, stable placeholders, model findings, verification blocking, Unicode browser offsets, chunking, and llama.cpp's chat contract. Compose validation checks all four deployment profiles. Hardware-specific GPU startup must be tested on matching hosts.

RedactThis is available under the [MIT License](LICENSE).
