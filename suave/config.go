package suave

type Config struct {
	Enabled        bool
	BeaconEndpoint string
}

var DefaultConfig = Config{
	Enabled:        false,
	BeaconEndpoint: "http://localhost:8546",
}
