package evidence

import (
	"fmt"
	"strings"

	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/google/uuid"
)

type ExecutionInput struct {
	Result        *pipeline.ExecutionResult
	Step          pipeline.AttackStep
	DecisionID    string
	PolicyVersion string
	ActorID       string
	IdentityAlias string
	Tool          string
	Verification  VerificationStatus
}

func RecordExecution(store Store, in ExecutionInput) (pipeline.Evidence, error) {
	if store == nil {
		return pipeline.Evidence{}, fmt.Errorf("evidence store unavailable")
	}
	if in.Result == nil {
		return pipeline.Evidence{}, fmt.Errorf("execution result is required")
	}
	if in.Result.CampaignID == uuid.Nil {
		return pipeline.Evidence{}, fmt.Errorf("campaign id is required")
	}
	if in.DecisionID == "" || in.PolicyVersion == "" || in.ActorID == "" {
		return pipeline.Evidence{}, fmt.Errorf("decision id, policy version and actor are required")
	}
	if in.Tool == "" {
		fields := strings.Fields(in.Step.Command)
		if len(fields) > 0 {
			in.Tool = fields[0]
		}
	}
	if in.Verification == "" {
		if in.Result.Success {
			in.Verification = VerificationVerified
		} else {
			in.Verification = VerificationUnverified
		}
	}
	rec, err := New(Input{
		CampaignID:      in.Result.CampaignID,
		ActionID:        in.Step.ID.String(),
		DecisionID:      in.DecisionID,
		PolicyVersion:   in.PolicyVersion,
		ActorID:         in.ActorID,
		IdentityAlias:   in.IdentityAlias,
		Tool:            in.Tool,
		Request:         []byte(in.Step.Command),
		Response:        []byte(in.Result.Output),
		Command:         in.Step.Command,
		RequestExcerpt:  in.Step.Command,
		ResponseExcerpt: in.Result.Output,
		Verification:    in.Verification,
	})
	if err != nil {
		return pipeline.Evidence{}, err
	}
	if err := store.Add(rec); err != nil {
		return pipeline.Evidence{}, err
	}
	return PipelineRef(rec, fmt.Sprintf("Runtime provenance for %s", in.Step.Name)), nil
}
