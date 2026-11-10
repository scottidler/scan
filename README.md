# scan
scan url/domain/ip

## Traceroute

scan keeps tracing the route while it runs, like `mtr`: each hop shows Loss%, Snt, Last, Avg,
Best, Wrst and StDev accumulated since the trace started, and a hop that answers from several
addresses lists them all. This needs `mtr` on the PATH; it is optional. When `mtr` is missing or
cannot run unprivileged, scan falls back to a `traceroute` snapshot every five minutes and says
why: the traceroute pane's status line and the `--no-tui` TRACEROUTE line both carry the reason
(for example `traceroute: mtr not installed`). The fallback lasts until scan restarts.

## Config

scan reads an optional `~/.config/scan/scan.yml` (or `$XDG_CONFIG_HOME/scan/scan.yml`). Its
`distrusted-cas` list adds entries to the built-in list of CA owners that browsers distrust; it
never replaces the built-ins. Each entry takes `name`, `source` (an `https://` URL),
`organizations` (issuer `O=` contains), `issuer-common-names` (issuer `CN=` equals) and an
optional `distrusted-after` date. At least one of `organizations` and `issuer-common-names` is
required.

A file that cannot be read, parsed or validated stops scan with an error naming the file; it is
never treated as empty. The `(distrusted CA)` mark is shown only in the TUI, not in `--no-tui` or
`--debug` output. See `scan.yml` at the repo root for an annotated example.

## License

scan is MIT licensed (`LICENSE`), except `src/scan/observatory/` and its test fixtures under
`tests/fixtures/observatory/`, which are derived from
[mdn/mdn-http-observatory](https://github.com/mdn/mdn-http-observatory) and are licensed under the
Mozilla Public License 2.0 (`LICENSE-MPL-2.0`). Each derived file names its upstream source in its
header. The port mirrors MIT and BSD licensed JavaScript packages and carries one CC BY 4.0
data table; their license texts are in `THIRD-PARTY-NOTICES`.
