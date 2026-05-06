package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	cli "github.com/urfave/cli/v2"

	"github.com/GoAsyncFunc/server-anytls/internal/app/server"
	"github.com/GoAsyncFunc/server-anytls/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

const (
	Name      = "anytls-node"
	CopyRight = "GoAsyncFunc@2025"
)

// Version is injected at build time via -ldflags "-X main.Version=...".
var Version = "dev"

func main() {
	cli.VersionPrinter = func(c *cli.Context) {
		fmt.Println(versionLine(c.App.Name, c.App.Version))
	}

	var config server.Config
	var apiConfig api.Config
	var serviceConfig service.Config
	var certConfig service.CertConfig

	app := BuildApp(&config, &apiConfig, &serviceConfig, &certConfig)

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

// BuildApp constructs the urfave/cli App with all flags wired to the supplied
// destinations. Exposed for tests so that flag parsing can be verified without
// invoking main().
func BuildApp(
	config *server.Config,
	apiConfig *api.Config,
	serviceConfig *service.Config,
	certConfig *service.CertConfig,
) *cli.App {
	app := &cli.App{
		Name:      Name,
		Version:   Version,
		Copyright: CopyRight,
		Usage:     "Provide AnyTLS service for V2Board",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "api",
				Usage:       "Server address",
				EnvVars:     []string{"API"},
				Destination: &apiConfig.APIHost,
			},
			&cli.StringFlag{
				Name:        "token",
				Usage:       "Token of server API",
				EnvVars:     []string{"TOKEN"},
				Destination: &apiConfig.Key,
			},
			&cli.StringFlag{
				Name:        "cert_file",
				Usage:       "Cert file",
				EnvVars:     []string{"CERT_FILE"},
				Value:       "/root/.cert/server.crt",
				DefaultText: "/root/.cert/server.crt",
				Destination: &certConfig.CertFile,
			},
			&cli.StringFlag{
				Name:        "key_file",
				Usage:       "Key file",
				EnvVars:     []string{"KEY_FILE"},
				Value:       "/root/.cert/server.key",
				DefaultText: "/root/.cert/server.key",
				Destination: &certConfig.KeyFile,
			},
			&cli.IntFlag{
				Name:        "node",
				Usage:       "Node ID",
				EnvVars:     []string{"NODE"},
				Destination: &apiConfig.NodeID,
			},
			&cli.DurationFlag{
				Name:        "fetch_users_interval",
				Aliases:     []string{"fui"},
				Usage:       "API request cycle(fetch users), unit: second",
				EnvVars:     []string{"FETCH_USER_INTERVAL"},
				Value:       time.Second * 60,
				DefaultText: "60",
				Destination: &serviceConfig.FetchUsersInterval,
			},
			&cli.DurationFlag{
				Name:        "report_traffics_interval",
				Aliases:     []string{"rti"},
				Usage:       "API request cycle(report traffics), unit: second",
				EnvVars:     []string{"REPORT_TRAFFICS_INTERVAL"},
				Value:       time.Second * 80,
				DefaultText: "80",
				Destination: &serviceConfig.ReportTrafficsInterval,
			},
			&cli.DurationFlag{
				Name:        "heartbeat_interval",
				Aliases:     []string{"hbi"},
				Usage:       "API request cycle(heartbeat), unit: second",
				EnvVars:     []string{"HEARTBEAT_INTERVAL"},
				Value:       time.Minute * 3,
				DefaultText: "180",
				Destination: &serviceConfig.HeartbeatInterval,
			},
			&cli.DurationFlag{
				Name:        "check_node_interval",
				Aliases:     []string{"cni"},
				Usage:       "API request cycle(check node config), unit: second",
				EnvVars:     []string{"CHECK_NODE_INTERVAL"},
				Destination: &serviceConfig.CheckNodeInterval,
			},
			&cli.StringFlag{
				Name:        "log_mode",
				Value:       server.LogLevelError,
				Usage:       "Log mode",
				EnvVars:     []string{"LOG_LEVEL"},
				Destination: &config.LogLevel,
			},
			&cli.BoolFlag{
				Name:        "allow-private-outbound",
				Aliases:     []string{"allow_private_outbound"},
				Usage:       "Allow outbound connections to private/reserved IP ranges",
				EnvVars:     []string{"ALLOW_PRIVATE_OUTBOUND"},
				Destination: &serviceConfig.AllowPrivateOutbound,
			},
		},
		Before: func(c *cli.Context) error {
			log.SetFormatter(&log.TextFormatter{})
			switch config.LogLevel {
			case server.LogLevelDebug:
				log.SetFormatter(&log.TextFormatter{FullTimestamp: true})
				log.SetLevel(log.DebugLevel)
				log.SetReportCaller(true)
			case server.LogLevelInfo:
				log.SetLevel(log.InfoLevel)
			case server.LogLevelError:
				log.SetLevel(log.ErrorLevel)
			default:
				return fmt.Errorf("log mode %s not supported", config.LogLevel)
			}
			return nil
		},
		Action: func(c *cli.Context) error {
			serviceConfig.Cert = certConfig

			if err := validateRequiredConfig(apiConfig); err != nil {
				return err
			}
			apiConfig.NodeType = api.AnyTls

			serv, err := server.New(config, apiConfig, serviceConfig)
			if err != nil {
				return fmt.Errorf("failed to create server: %w", err)
			}
			if err := serv.Start(); err != nil {
				serv.Close()
				return fmt.Errorf("failed to start server: %w", err)
			}

			defer func() {
				if e := recover(); e != nil {
					log.Errorf("panic: %v", e)
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					log.Errorf("stack trace:\n%s", buf[:n])
					serv.Close()
					os.Exit(1)
				} else {
					serv.Close()
				}
			}()

			osSignals := make(chan os.Signal, 1)
			signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
			<-osSignals
			return nil
		},
	}

	app.Commands = []*cli.Command{
		{
			Name:    "version",
			Aliases: []string{"v"},
			Usage:   "Show version information",
			Action: func(c *cli.Context) error {
				fmt.Println(versionLine(Name, Version))
				return nil
			},
		},
	}

	return app
}

func versionLine(appName, appVersion string) string {
	return fmt.Sprintf("%s version %s", appName, appVersion)
}

func validateRequiredConfig(apiConfig *api.Config) error {
	if strings.TrimSpace(apiConfig.APIHost) == "" {
		return fmt.Errorf("api is required")
	}
	if strings.TrimSpace(apiConfig.Key) == "" {
		return fmt.Errorf("token is required")
	}
	if apiConfig.NodeID <= 0 {
		return fmt.Errorf("node is required")
	}
	return nil
}
