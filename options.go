package ghinstallation

// Option is a functional parameter interface used by the constructor
type Option func(*Transport) error

// WithEnterpriseGithub is a functional parameter to configure a custom github API server.
func WithEnterpriseGithub(baseURL string) Option {
	return func(transport *Transport) error {
		if baseURL != "" {
			transport.BaseURL = baseURL
		}
		return nil
	}
}
