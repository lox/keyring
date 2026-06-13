package keyring

import "fmt"

type options struct {
	serviceName    string
	backends       []Backend
	providers      []Provider
	fallbackPolicy FallbackPolicy
}

// Option configures Open.
type Option func(*options) error

// WithServiceName sets the service name used by providers that group items by
// application or service.
func WithServiceName(name string) Option {
	return func(o *options) error {
		o.serviceName = name
		return nil
	}
}

// WithBackends sets the backend order to try. If unset, Open tries available
// providers in default order.
func WithBackends(backends ...Backend) Option {
	return func(o *options) error {
		for _, backend := range backends {
			if backend == InvalidBackend {
				return fmt.Errorf("%w: backend is empty", ErrInvalidOption)
			}
		}
		o.backends = append([]Backend(nil), backends...)
		return nil
	}
}

// WithProvider adds or replaces one provider.
func WithProvider(provider Provider) Option {
	return WithProviders(provider)
}

// WithProviders adds or replaces providers. A provider with the same backend as
// an existing provider replaces it for this Open call.
func WithProviders(providers ...Provider) Option {
	return func(o *options) error {
		for _, provider := range providers {
			if provider.Backend == InvalidBackend {
				return fmt.Errorf("%w: %w", ErrInvalidOption, errProviderBackendEmpty)
			}
			if provider.Open == nil {
				return fmt.Errorf("%w: %s: %w", ErrInvalidOption, provider.Backend, errProviderOpenNil)
			}
		}
		o.providers = append(o.providers, providers...)
		return nil
	}
}

// WithFallbackPolicy controls when Open tries the next provider after an open
// error.
func WithFallbackPolicy(policy FallbackPolicy) Option {
	return func(o *options) error {
		switch policy {
		case FallbackOnUnavailable, FallbackOnError:
			o.fallbackPolicy = policy
			return nil
		default:
			return fmt.Errorf("%w: unknown fallback policy %d", ErrInvalidOption, policy)
		}
	}
}

func newOptions(opts []Option) (options, error) {
	cfg := options{
		providers:      DefaultProviders(),
		fallbackPolicy: FallbackOnUnavailable,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(&cfg); err != nil {
			return options{}, err
		}
	}
	return cfg, nil
}
