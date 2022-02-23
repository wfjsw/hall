package main

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
)

type UsageArgs struct {
	Cmd            string
	Release        string
	Version        string
	BuildDate      string
	GoVer          string
	OS             string
	Arch           string
	DefaultDataDir string
}

var usageTmpl = `Usage: {{.Cmd}} [options]

{{.Release}} {{.Version}}
Built on {{.BuildDate}}
Target: {{.GoVer}} {{.OS}} {{.Arch}}

 --help
     Shows this help listing

 --config <config-path> (default: config.json)
     Configuration file

 --datadir <data-dir> (default: ./data)
     Directory to use for server storage

 --log <log-path>
     Log file path.

 --pprof <address> 
     Launch runtime profiling on address

 --regen-keys
     Regenerate certificate and keys

`

type args struct {
	ShowHelp   bool
	ConfigPath string
	DataDir    string
	LogPath    string
	PProf      string
	RegenKeys  bool
	SQLiteDB   string
	CleanUp    bool
}

func defaultDataDir() string {
	cwd, _ := os.Getwd()
	dirname := "data"
	return filepath.Join(cwd, dirname)
}

func defaultConfigPath() string {
	cwd, _ := os.Getwd()

	return filepath.Join(cwd, "config.json")
}

func Usage() {
	t, err := template.New("usage").Parse(usageTmpl)
	if err != nil {
		panic("unable to parse usage template")
	}

	err = t.Execute(os.Stdout, UsageArgs{
		Cmd:            os.Args[0],
		Release:        verRelease,
		Version:        VERSION,
		BuildDate:      BUILDDATE,
		GoVer:          runtime.Version(),
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		DefaultDataDir: defaultDataDir(),
	})
	if err != nil {
		panic("unable to execute usage template")
	}
}

var Args args

func init() {
	flag.Usage = Usage

	flag.BoolVar(&Args.ShowHelp, "help", false, "")
	flag.StringVar(&Args.ConfigPath, "config", defaultConfigPath(), "")
	flag.StringVar(&Args.DataDir, "datadir", defaultDataDir(), "")
	flag.StringVar(&Args.LogPath, "log", "", "")
	flag.StringVar(&Args.PProf, "pprof", "", "")
	flag.BoolVar(&Args.RegenKeys, "regen-keys", false, "")

	flag.StringVar(&Args.SQLiteDB, "import-murmurdb", "", "")
	flag.BoolVar(&Args.CleanUp, "cleanup", false, "")
}
