# Contributing

1. Read and sign the [CLA](CLA.md). The bot asks on your first pull request.
2. Keep the agent's promises (see README): read-only, no inbound connections,
   no file contents or secrets leave the server.
3. New checks are deterministic rules with a test that fails if the rule breaks.
   Tests build a fake filesystem under `t.TempDir()`; see `check/*_test.go`.
4. `go vet ./... && go test ./...` must pass.
