package evidence

import (
	"fmt"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
)

func PipelineRef(r Record, description string) pipeline.Evidence {
	return pipeline.Evidence{
		Type:          "provenance_record",
		Content:       fmt.Sprintf("evidence:%s", r.ID),
		Timestamp:     r.CreatedAt,
		Description:   description,
		RecordID:      r.ID.String(),
		IntegrityHash: r.IntegrityHash,
	}
}
