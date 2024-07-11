# `bpf-prog-info` Input Plugin

Collects metadata information on BPF programs loaded on the host.

## Configuration

```conf
# Fetch metadata metrics from BPF programs on the host.
[[inputs.bpf_prog]]
  ## Optional tags

  ## Hash of the program instructions.
  ##
  ## Corresponds to `tag` field in `bpf_prog_info`.
  tag = true
  ## ID of the BTF object.
  ##
  ## Corresponds to `btf_id` field in `bpf_prog_info`.
  btf_id = true

  ## Optional field

  ## Size of program's JIT-compiled machine code and translated bytecode in bytes.
  ##
  ## Corresponds to `jited_prog_len` & `xlated_prog_len` field in `bpf_prog_info`.
  prog_len = true

  ## When the program was loaded since boot time in nanoseconds.
  ##
  ## Corresponds to `load_time` field in `bpf_prog_info`.
  time_loaded = true

  ## User ID of the process who loaded the program.
  ##
  ## Corresponds to `created_by_uid` field in `bpf_prog_info`.
  created_by_uid = true

  ## ID of maps used by the program as a string.
  ##
  ## Corresponds to `map_ids` field in `bpf_prog_info`.
  map_ids = true

  ## Collects runtime (nanoseconds) & run count statistics of the program.
  ## NOTE: This executes the `BPF_ENABLE_STATS` syscall command.
  ##
  ## Corresponds to `run_time` & `run_cnt` field in `bpf_prog_info`.
  statistics = true

  ## Amount of times the "recursion prevention" mechanism kicks in.
  ##
  ## Corresponds to `recursion_misses` field in `bpf_prog_info`.
  recursion_misses = true

  ## Number of verified instructions in the program.
  ##
  ## Corresponds to `verified_insns` field in `bpf_prog_info`.
  verified_instructions = true
```

## Metrics

These metrics are extracted from the `bpf_prog_info` object.

- bpf_prog
  - tags:
    - id
    - type
    - name
    - tag (optional)
    - btf_id (optional)
  - fields:
    - jited_size (integer, bytes)
    - xlated_size (integer, bytes)
    - time_loaded (integer, nanoseconds)
    - created_by_uid (integer)
    - map_ids (string)
    - run_time (integer, nanoseconds)
    - run_count (integer, count)
    - recursion_misses (integer, count)
    - verified_instructions (integer, count)

## Usage

Build binary:

```golang
go build -o bpf-prog cmd/main.go
```

Execute binary:

```golang
sudo ./bpf-prog -config plugin.conf
```
