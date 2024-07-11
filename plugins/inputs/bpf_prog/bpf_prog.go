package bpf_prog

import (
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
	"golang.org/x/sys/unix"
)

var sampleConfig string = ``

type BpfProgram struct {
	bpfEnableStats io.Closer

	Tag   bool `toml:"tag"`
	BTFID bool `toml:"btf_id"`

	ProgLen         bool `toml:"code_size"`
	LoadTime        bool `toml:"time_loaded"`
	CreatedByUID    bool `toml:"created_by_uid"`
	MapIDs          bool `toml:"map_ids"`
	ProgStats       bool `toml:"statistics"`
	RecursionMisses bool `toml:"recursion_misses"`
	VerifiedInsns   bool `toml:"verified_instructions"`

	Log telegraf.Logger `toml:"-"`
}

func (*BpfProgram) SampleConfig() string {
	return sampleConfig
}

func (p *BpfProgram) Gather(acc telegraf.Accumulator) error {
	// Iterate over bpf programs loaded on the host
	prev := ebpf.ProgramID(0)
	for {
		prog_id, err := ebpf.ProgramGetNextID(prev)
		// Exit when finish iterating over all programs
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			prev = prog_id
			continue
		}

		prog, err := ebpf.NewProgramFromID(prog_id)
		if err != nil {
			prev = prog_id
			continue
		}

		info, err := prog.Info()
		if err != nil {
			prev = prog_id
			continue
		}
		if info.Name == "" {
			prev = prog_id
			continue
		}
		now := time.Now()

		// Fields
		fields := map[string]interface{}{}
		if p.ProgLen {
			fields["jited_size"] = info.JitedSize
			fields["xlated_size"] = info.TranslatedSize
		}
		if p.LoadTime {
			fields["time_loaded"] = info.LoadTime.Nanoseconds()
		}
		if p.CreatedByUID {
			uid, isAvailable := info.CreatedByUID()
			if isAvailable {
				fields["created_by_uid"] = uid
			}
		}
		if p.MapIDs {
			maps, isAvailable := info.MapIDs()
			if isAvailable {
				fields["map_ids"] = strings.Trim(strings.Replace(fmt.Sprint(maps), " ", ",", -1), "[]")
			}
		}
		if p.ProgStats {
			if p.bpfEnableStats != nil {
				run_time, rtAvailable := info.Runtime()
				run_cnt, rcAvailable := info.RunCount()
				if rtAvailable && rcAvailable {
					fields["run_time"] = uint64(run_time.Nanoseconds())
					fields["run_count"] = run_cnt
				}
			} else {
				p.Log.Warnf("program %v: `BPF_ENABLE_STATS` not enabled")
			}
		}
		if p.RecursionMisses {
			recursion_misses, isAvailable := info.RecursionMisses()
			if isAvailable {
				fields["recursion_misses"] = recursion_misses
			}
		}
		if p.VerifiedInsns {
			fields["verified_instructions"] = info.VerifiedInstructions
		}

		// Tags
		tags := map[string]string{
			"id":   strconv.FormatUint(uint64(prog_id), 10),
			"type": info.Type.String(),
			"name": info.Name,
		}
		if p.Tag {
			tags["tag"] = info.Tag
		}
		if p.BTFID {
			btfId, isAvailable := info.BTFID()
			if isAvailable {
				tags["btf_id"] = strconv.FormatUint(uint64(btfId), 10)
			}
		}

		acc.AddFields("bpf_prog", fields, tags, now)
		prev = prog_id
	}

	return nil
}

func (p *BpfProgram) Init() error {
	if p.ProgStats {
		fd, err := ebpf.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			p.Log.Errorf("`BPF_ENABLE_STATS` syscall failed: %v", err)
		}
		p.bpfEnableStats = fd
	}
	// defer func() {
	// 	if p.bpfEnableStats != nil {
	// 		p.bpfEnableStats.Close()
	// 	}
	// }()

	return nil
}

func init() {
	inputs.Add("bpf_prog", func() telegraf.Input {
		return &BpfProgram{
			bpfEnableStats: nil,
			LoadTime:       true,
		}
	})
}
