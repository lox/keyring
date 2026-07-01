package keyring

import (
	"context"
	"fmt"
)

// FileOption configures the built-in encrypted file provider.
type FileOption func(*fileConfig)

type fileConfig struct {
	dir    string
	prompt PromptFunc
}

// FileDir sets the encrypted file backend directory.
func FileDir(dir string) FileOption {
	return func(cfg *fileConfig) { cfg.dir = dir }
}

// FilePrompt sets the encrypted file backend password prompt.
func FilePrompt(prompt PromptFunc) FileOption {
	return func(cfg *fileConfig) { cfg.prompt = prompt }
}

// FileProvider returns the built-in encrypted file provider.
func FileProvider(opts ...FileOption) Provider {
	cfg := fileConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return Provider{
		Backend: FileBackend,
		Open: func(ctx context.Context, _ OpenOptions) (Keyring, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if cfg.dir == "" {
				return nil, fmt.Errorf("%w: file backend requires FileDir", ErrUnavailable)
			}
			if cfg.prompt == nil {
				return nil, fmt.Errorf("%w: file backend requires FilePrompt", ErrInvalidOption)
			}
			return &fileKeyring{
				dir:          cfg.dir,
				passwordFunc: cfg.prompt,
			}, nil
		},
	}
}
