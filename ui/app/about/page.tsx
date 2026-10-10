import { Panel, PageHeader, Pill, Because } from "@/components/primitives";
import { availableCommands, isPermitted, withheldCommands } from "@/lib/thn";

/**
 * What this console can and cannot do, on the console itself.
 *
 * A monitoring tool that fails silently is worse than no tool, and the failure
 * mode of a console in particular is looking authoritative while showing
 * nothing. So the boundary is stated here, in the application, rather than only
 * in a README nobody opens.
 */
export default function AboutPage() {
  return (
    <>
      <PageHeader
        title="About"
        plain="What this console shows you, and the one thing it deliberately cannot do."
      />

      <Panel title="Plain-language glossary" note="The words this console uses, and what they mean">
        <dl className="panel-body grid gap-x-8 gap-y-3 sm:grid-cols-2">
          {[
            ["Gateway", "The box that sits between your internet connection and your devices. It is what this console manages."],
            ["WAN", "Your connection to the internet — the cable running out to your provider."],
            ["LAN", "Your own local network, the one your devices are on."],
            ["Device", "Anything connected to your network: a phone, a laptop, a TV, a printer."],
            ["Zone / VLAN", "A separate group of devices kept apart from the others, so they cannot see each other."],
            ["Isolation", "Stopping devices in the same group from talking directly to each other."],
            ["DHCP", "The service that automatically hands out addresses to devices that join."],
            ["DNS", "The service that turns a name like example.com into an address."],
            ["Speed limit", "A cap on how much bandwidth a device may use, so one device cannot slow down everything else."],
            ["Schedule", "A time window during which a setting applies, such as a slower limit overnight."],
            ["Rule", "One automatic check. Each has a name, how serious it is, and how long a fault must last before you are told."],
            ["Incident", "A problem the gateway has decided is real, worked out from what its rules found."],
            ["Pending", "A fault that is happening but has not lasted long enough to be reported yet."],
            ["Undecidable", "A check whose input could not be read. This is not the same as the check being fine."],
            ["Fail-closed", "If the gateway cannot read the state of the network, it stops rather than letting traffic through unchecked."],
            ["Preview", "A configuration written out as text, not applied."],
          ].map(([term, meaning]) => (
            <div key={term}>
              <dt className="text-xs font-semibold text-ink-100">{term}</dt>
              <dd className="mt-0.5 text-2xs leading-relaxed text-ink-400">{meaning}</dd>
            </div>
          ))}
        </dl>
      </Panel>

      <Panel title="The boundary">
        <div className="panel-body space-y-3 text-xs leading-relaxed text-ink-300">
          <p>
            This console has no write path. It cannot apply a configuration,
            change a route, restart a service, or write to the gateway&apos;s
            state. There is no button that would do any of those things, because
            there is nothing behind it to do them.
          </p>
          <p>
            The Go binary cannot do them either. That is not a restriction this
            console inherited — it is the property the whole project is built
            around, and it is enforced in the Go side by a package that permits
            exactly one package to spawn a process, and within it only
            read-only verbs.
          </p>
          <p>
            The two together mean a reader can take any claim on this console at
            face value. It is showing what a read-only tool observed, and
            nothing has been changed.
          </p>
        </div>
      </Panel>

      <Panel
        title="Withheld"
        note="commands this console will not run, and why"
      >
        <div className="panel-body space-y-3">
          {withheldCommands.map((c) => (
            <div key={c.command}>
              <div className="mb-1 flex items-center gap-2">
                <code className="value text-critical-fg">thn {c.command}</code>
                <Pill>not permitted</Pill>
              </div>
              <Because>{c.why}</Because>
            </div>
          ))}
          <p className="text-2xs text-ink-500">
            The refusal is enforced in <code>ui/lib/thn.ts</code>, which is the
            only file in this application that spawns a process. Arguments are
            passed as an array and never interpolated into a shell string, so a
            configuration path containing a space or a semicolon is data rather
            than a command.
          </p>
        </div>
      </Panel>

      <Panel
        title="What it will run"
        note="every subcommand reachable from here"
      >
        <div className="panel-body">
          <div className="flex flex-wrap gap-1.5">
            {availableCommands.map((c) => (
              <span
                key={c}
                className="inline-flex items-center gap-1 rounded border border-ink-700 bg-ink-850 px-2 py-1 font-mono text-2xs text-ink-200"
              >
                thn {c}
              </span>
            ))}
            {!isPermitted("activate") ? (
              <span className="text-2xs text-ink-500">
                and not <code>thn activate</code>
              </span>
            ) : null}
          </div>
        </div>
      </Panel>

      <Panel title="How the data reaches here">
        <div className="panel-body space-y-2 text-xs leading-relaxed text-ink-300">
          <p>
            The console invokes <code>thn --json</code> and renders the result.
            It reimplements none of the Go side&apos;s logic, deliberately: a
            second implementation would be a second thing that could disagree
            with the first about what a gateway is doing, and there would be no
            way to tell which one was right.
          </p>
          <p>
            That makes the console exactly as capable as the binary, which is the
            property that keeps it safe. It also means{" "}
            <code>THN_BINARY</code> must point at a built binary, and without
            one every page reports that rather than rendering an empty result.
          </p>
          <p className="text-2xs text-ink-500">
            Set <code>THN_BINARY=/path/to/thn</code> to use a specific build, and{" "}
            <code>THN_ROOT</code> or <code>THN_CONFIG</code> to point it at a
            particular gateway configuration.
          </p>
        </div>
      </Panel>

      <Panel title="Where the gateway is">
        <div className="panel-body text-xs leading-relaxed text-ink-300">
          <p>
            Intended for the gateway itself, where the binary is installed and
            the console reads the local host. On a development machine it works
            against a local <code>thn</code> build, which is enough to review
            configuration and exercise the rules but says nothing about a remote
            device.
          </p>
        </div>
      </Panel>
    </>
  );
}
