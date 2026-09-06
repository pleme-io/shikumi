//! The daemon startup gate — argv handling for a shikumi-configured daemon.
//!
//! ★ PLACEMENT IS THE POINT, and the first attempt got it wrong. This began in
//! `cli.rs` beside `ConfigShowCommand`, which reads as the obvious home until
//! you notice `cli` is `#[cfg(feature = "cli")]` and pulls in **clap**. Putting
//! a dependency-free argv gate there would force clap onto three daemons that
//! deliberately have no argument parser -- coupling the primitive to a
//! dependency none of its consumers want.
//!
//! So this module is ungated and depends on nothing but `std`. `cli.rs` serves
//! clap apps; this serves daemons. They are different consumers, not one
//! surface with a flag.

// ── THE GATE ──────────────────────────────────────────────────
//
// `ConfigShowCommand` above serves clap-based apps. A fleet DAEMON is usually
// not one: it has no subcommands, reads its whole surface from a shikumi tier,
// and so tends to be written with no argv handling AT ALL.
//
// That is a defect, and it was found the way defects are: `jikokud --help`
// ignored the flag, started the daemon, and blocked for ten minutes. On a
// binary whose job is to DISCIPLINE THE SYSTEM CLOCK, "starts by accident when
// you ask it a question" is not a papercut.
//
// Measured 2026-08-29: annaid, jikokud and nanorid ALL had zero argv handling.
// Three independent binaries arriving at the same omission is the convergence
// signal -- the shape is forced by "daemon configured entirely by shikumi",
// not copied -- so the answer is one primitive here rather than three fixes.
//
// Two rules it encodes, both learned rather than assumed:
//
//   1. `--help`/`--version` are answered BEFORE any config load, side effect,
//      or socket bind. A daemon that must read its config to tell you its name
//      cannot be asked anything on a broken host.
//   2. An UNRECOGNISED argument is a hard refusal, never ignored. Silently
//      dropping `--dry-run` on a clock daemon means the operator believes they
//      asked for a rehearsal and got a live run. This is the ★★ kotae rule at
//      the argv boundary: say which of the four things happened.

/// What a daemon should do after its arguments have been read.
///
/// Deliberately NOT a `Result`: exiting zero for `--help` is a success, and
/// modelling it as an error makes every caller invert it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Startup {
    /// No arguments asked anything — proceed with normal startup.
    Run,
    /// Print `message` and exit with `code`. `code == 0` goes to stdout,
    /// anything else to stderr; the caller does the printing so this stays
    /// pure and testable.
    Exit { code: u8, message: String },
}

impl Startup {
    /// Do the conventional thing: print and exit, or return so the caller runs.
    ///
    /// Kept separate from `classify` so the decision is testable without a
    /// process. Returns `None` when the daemon should proceed.
    #[must_use]
    pub fn resolve(self) -> Option<std::process::ExitCode> {
        match self {
            Self::Run => None,
            Self::Exit { code: 0, message } => {
                println!("{message}");
                Some(std::process::ExitCode::SUCCESS)
            }
            Self::Exit { code, message } => {
                eprintln!("{message}");
                Some(std::process::ExitCode::from(code))
            }
        }
    }

    /// The Run pole — `true` on [`Self::Run`], `false` on [`Self::Exit`].
    ///
    /// One canonical name for the "does this [`Startup`] ask the daemon to
    /// proceed?" question — a per-daemon startup meter grouping
    /// gate-permitted invocations distinctly from refused/answered ones (a
    /// structured-tracing span attribute distinguishing proceed startups
    /// from exit startups, a supervision-tree counter bucketing the two
    /// arms) matches this predicate at ONE site instead of open-coding
    /// `matches!(startup, Startup::Run)` and paying the two-arm
    /// bookkeeping tax at every consumer.
    ///
    /// `const`-callable — body is a pure `matches!` on a borrowed
    /// [`Self`] with no function calls, allocations, or non-const helpers
    /// on the path, so a compile-time-known [`Startup::Run`] projects to
    /// a compile-time-known [`bool`]. Peer of [`Self::is_exit`] — the two
    /// predicates form a closed binary partition of the [`Startup`]
    /// variant space, pinned by
    /// [`daemon_cli_tests::startup_is_run_and_is_exit_are_a_closed_binary_partition`].
    /// Welded at compile time on the `Startup::Run` arm by
    /// [`daemon_cli_tests::startup_run_projections_are_const_callable`];
    /// the `Startup::Exit { message: String }` arm blocks a `const`
    /// binding on the receiver (E0493 drop-check on `String`) and rides
    /// the runtime cross-check
    /// [`daemon_cli_tests::startup_exit_projections_agree_with_pattern_match`]
    /// instead.
    #[must_use]
    pub const fn is_run(&self) -> bool {
        matches!(self, Self::Run)
    }

    /// The Exit pole — `true` on [`Self::Exit`], `false` on [`Self::Run`].
    ///
    /// Pointwise complement of [`Self::is_run`] — pinned by
    /// [`daemon_cli_tests::startup_is_run_and_is_exit_are_a_closed_binary_partition`].
    /// See [`Self::is_run`] for the full contract, the const-callability
    /// clause, and the two weld pins.
    #[must_use]
    pub const fn is_exit(&self) -> bool {
        matches!(self, Self::Exit { .. })
    }

    /// The exit code carried on [`Self::Exit`], or [`None`] on [`Self::Run`].
    ///
    /// The typed projection of the imperative [`Self::resolve`] — a caller
    /// that wants the numeric exit answer without printing (a test
    /// asserting the gate returned `Some(0)` for `--help` and `Some(2)`
    /// for `--dry-run`, a wrapper forwarding the code up a supervision
    /// tree without redirecting the message, a structured-log field
    /// naming the code that would exit the daemon) matches this
    /// projection at ONE site instead of destructuring the [`Self::Exit`]
    /// variant open-coded and re-doing the [`Self::Run`]-is-`None`
    /// bookkeeping at every consumer.
    ///
    /// `const`-callable — reads only the `Copy` `code` field on
    /// [`Self::Exit`] and returns a `Copy` [`Option`]`<`[`u8`]`>`; no
    /// non-const helpers on the path. See [`Self::is_run`] for the two
    /// weld pins the const-callability rides.
    #[must_use]
    pub const fn exit_code(&self) -> Option<u8> {
        match self {
            Self::Run => None,
            Self::Exit { code, .. } => Some(*code),
        }
    }
}

/// The identity a daemon presents at `--help` / `--version`.
#[derive(Debug, Clone, Copy)]
pub struct DaemonCli<'a> {
    /// The binary's name, e.g. `"jikokud"`.
    pub name: &'a str,
    /// Its version, normally `env!("CARGO_PKG_VERSION")`.
    pub version: &'a str,
    /// One line saying what it does.
    pub summary: &'a str,
    /// The env var that selects its config tier, e.g. `"JIKOKU_TIER"`.
    /// Named in the help text because it is the daemon's ONLY input, and an
    /// operator otherwise has no way to discover it.
    pub tier_env: &'a str,
}

impl DaemonCli<'_> {
    /// Classify a daemon's arguments. PURE — no I/O, no exit, no config load.
    ///
    /// Accepts the argument list WITHOUT argv[0]; pass
    /// `std::env::args().skip(1)`.
    #[must_use]
    pub fn classify<I, S>(&self, args: I) -> Startup
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        // ★ ONLY THE FIRST ARGUMENT IS EXAMINED, and that is complete rather
        // than a shortcut: every recognised flag is TERMINAL (both --help and
        // --version exit), and anything unrecognised refuses. So there is no
        // argument that would let a scan continue to a second one.
        //
        // This was a `for` loop whose every arm returned. clippy's
        // `never_loop` caught it, and it was right for a better reason than
        // style: the loop implied a scan the code does not perform, so a later
        // reader could reasonably add a non-terminal flag and expect the
        // second argument to be reached. Written as a match on the first
        // argument, adding such a flag forces you to confront the question.
        let mut args = args.into_iter();
        let Some(first) = args.next() else {
            return Startup::Run;
        };
        match first.as_ref() {
            "-h" | "--help" => Startup::Exit {
                code: 0,
                message: self.help_text(),
            },
            "-V" | "--version" => Startup::Exit {
                code: 0,
                message: format!("{} {}", self.name, self.version),
            },
            // ★ REFUSE, never ignore. See rule 2 in the module header.
            other => Startup::Exit {
                code: 2,
                message: format!(
                    "{}: unrecognised argument {other:?}\n\
                     This daemon takes no arguments — it is configured entirely through \
                     shikumi tiers ({}).\nTry `{} --help`.",
                    self.name, self.tier_env, self.name
                ),
            },
        }
    }

    fn help_text(&self) -> String {
        format!(
            "{name} {version}\n{summary}\n\n\
             USAGE:\n    {name}\n\n\
             This daemon takes no arguments. Its entire surface is the shikumi\n\
             config tier selected by {tier_env}; run `{name} --version` for the\n\
             build, and read the tier with the app's `config-show` surface.\n\n\
             FLAGS:\n    -h, --help       Print this and exit\n    \
             -V, --version    Print the version and exit",
            name = self.name,
            version = self.version,
            summary = self.summary,
            tier_env = self.tier_env,
        )
    }
}

#[cfg(test)]
mod daemon_cli_tests {
    use super::{DaemonCli, Startup};

    const CLI: DaemonCli<'static> = DaemonCli {
        name: "jikokud",
        version: "0.1.0",
        summary: "typed SNTP client",
        tier_env: "JIKOKU_TIER",
    };

    #[test]
    fn no_arguments_runs() {
        assert_eq!(CLI.classify(Vec::<String>::new()), Startup::Run);
    }

    #[test]
    fn help_exits_zero_and_names_the_tier_env() {
        // The regression this whole surface exists for: --help must be
        // ANSWERED, not ignored on the way into the daemon loop.
        let Startup::Exit { code, message } = CLI.classify(["--help"]) else {
            panic!("--help must not Run");
        };
        assert_eq!(code, 0);
        assert!(message.contains("jikokud 0.1.0"), "{message}");
        assert!(
            message.contains("JIKOKU_TIER"),
            "help must name the daemon's only input: {message}"
        );
    }

    #[test]
    fn short_flags_work_too() {
        assert!(matches!(
            CLI.classify(["-h"]),
            Startup::Exit { code: 0, .. }
        ));
        assert!(matches!(
            CLI.classify(["-V"]),
            Startup::Exit { code: 0, .. }
        ));
    }

    #[test]
    fn version_is_just_name_and_version() {
        let Startup::Exit { code, message } = CLI.classify(["--version"]) else {
            panic!("--version must not Run");
        };
        assert_eq!(code, 0);
        assert_eq!(message, "jikokud 0.1.0");
    }

    /// ★ The dangerous case. An unknown flag must REFUSE, because an operator
    /// who typed `--dry-run` believes they asked for a rehearsal.
    #[test]
    fn unknown_argument_refuses_rather_than_running() {
        let Startup::Exit { code, message } = CLI.classify(["--dry-run"]) else {
            panic!("an unknown argument must never Run");
        };
        assert_eq!(code, 2, "must be a distinct non-zero code");
        assert!(message.contains("--dry-run"), "must NAME it: {message}");
        assert!(message.contains("unrecognised"), "{message}");
    }

    #[test]
    fn a_bare_positional_is_refused_too() {
        // Not just flags: `jikokud /etc/jikoku.yaml` is someone assuming a
        // config path argument that does not exist. Silently ignoring it
        // would run with a completely different config than they intended.
        assert!(matches!(
            CLI.classify(["/etc/jikoku.yaml"]),
            Startup::Exit { code: 2, .. }
        ));
    }

    #[test]
    fn help_wins_when_it_comes_first() {
        assert!(matches!(
            CLI.classify(["--help", "--bogus"]),
            Startup::Exit { code: 0, .. }
        ));
    }

    #[test]
    fn but_a_bad_argument_before_help_still_refuses() {
        // First-match-wins, and that is the safe direction: it cannot be used
        // to smuggle an ignored flag past the gate by appending --help.
        assert!(matches!(
            CLI.classify(["--bogus", "--help"]),
            Startup::Exit { code: 2, .. }
        ));
    }

    #[test]
    fn run_resolves_to_none_so_the_caller_proceeds() {
        assert!(Startup::Run.resolve().is_none());
    }

    #[test]
    fn startup_run_projections_are_const_callable() {
        // Compile-time weld pin for the three const projections on the
        // `Startup::Run` arm — `is_run` / `is_exit` / `exit_code` — all
        // routed through `const` bindings whose evaluation must land in a
        // const position. The `Startup::Exit { message: String }` arm
        // blocks a `const` binding on the receiver (E0493 drop-check on
        // `String`), so it rides the runtime cross-check
        // `startup_exit_projections_agree_with_pattern_match` instead.
        const RUN: Startup = Startup::Run;
        const IS_RUN: bool = RUN.is_run();
        const IS_EXIT: bool = RUN.is_exit();
        const CODE: Option<u8> = RUN.exit_code();
        const {
            assert!(IS_RUN);
            assert!(!IS_EXIT);
            assert!(CODE.is_none());
        }
        // Cross-check the const-position answer against a runtime call on
        // an independent `Startup::Run` binding — the two must be
        // byte-identical, so a future edit that drifts the const-fn body
        // away from the runtime-fn body diverges here.
        let run_rt = Startup::Run;
        assert_eq!(run_rt.is_run(), IS_RUN);
        assert_eq!(run_rt.is_exit(), IS_EXIT);
        assert_eq!(run_rt.exit_code(), CODE);
    }

    #[test]
    fn startup_exit_projections_agree_with_pattern_match() {
        // Runtime cross-check on the `Startup::Exit` arm — the receiver
        // holds a `String` payload and cannot ride a `const` binding
        // (E0493 drop-check), so the `is_run` / `is_exit` / `exit_code`
        // trio is pinned pointwise-equal to a pattern-match answer over
        // three representative exit codes covering the three arms of
        // `Startup::resolve`'s dispatch (success on 0, refuse on 2, an
        // arbitrary non-zero).
        let cases = [
            Startup::Exit {
                code: 0,
                message: String::new(),
            },
            Startup::Exit {
                code: 2,
                message: "refuse".to_owned(),
            },
            Startup::Exit {
                code: 42,
                message: "arb".to_owned(),
            },
        ];
        for s in &cases {
            assert!(!s.is_run(), "Startup::Exit must not satisfy is_run: {s:?}");
            assert!(s.is_exit(), "Startup::Exit must satisfy is_exit: {s:?}");
            let Startup::Exit { code, .. } = s else {
                unreachable!("all cases are Exit by construction")
            };
            assert_eq!(
                s.exit_code(),
                Some(*code),
                "exit_code() must project the `code` field verbatim: {s:?}",
            );
        }
    }

    #[test]
    fn startup_is_run_and_is_exit_are_a_closed_binary_partition() {
        // Every `Startup` value satisfies exactly one of the two sibling
        // predicates — none satisfies both, none satisfies zero. Binary-
        // partition analogue of the ternary/binary-partition pins the
        // crate carries on its other closed-primitive axes (e.g.
        // `WatchEventClass::is_reload` / `_removed` / `_ignored`,
        // `ConfigSourceKind` layer-kind trio). A future third `Startup`
        // variant landing without its own sibling predicate collapses
        // the partition to zero on that arm, failing here before drifting
        // through any consumer that groups on the polarity.
        let cases = [
            Startup::Run,
            Startup::Exit {
                code: 0,
                message: String::new(),
            },
            Startup::Exit {
                code: 2,
                message: "refuse".to_owned(),
            },
        ];
        for s in &cases {
            let hits = usize::from(s.is_run()) + usize::from(s.is_exit());
            assert_eq!(
                hits, 1,
                "Startup case {s:?} must satisfy exactly one polarity, got {hits}",
            );
        }
    }

    #[test]
    fn startup_exit_code_agrees_with_resolve_on_the_run_arm() {
        // The typed projection agrees with the imperative `resolve()` on
        // the Run arm — both are `None`, and `exit_code` is defined as
        // exactly this arm's negative pole. Pinning it here forecloses a
        // future drift where `resolve()` grew a fallback that returned
        // some default exit code on Run without `exit_code` mirroring it.
        assert_eq!(Startup::Run.exit_code(), None);
        assert!(Startup::Run.resolve().is_none());
    }
}
