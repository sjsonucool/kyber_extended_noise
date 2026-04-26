#[cfg(not(feature = "hazmat"))]
fn main() {
    eprintln!(
        "This example requires hazmat APIs. Run with: cargo run --release --example epp_reliability_sweep --features hazmat -- [args]"
    );
    std::process::exit(1);
}

#[cfg(feature = "hazmat")]
mod app {
    use pqc_kyber::{
        decapsulate_with_epp_bound, encapsulate_with_epp_bound, keypair,
        params::{
            KYBER_EPP_UNIFORM_BOUND, KYBER_INDCPA_BYTES, KYBER_INDCPA_PUBLICKEYBYTES,
            KYBER_INDCPA_SECRETKEYBYTES, KYBER_K, KYBER_N, KYBER_Q, KYBER_SYMBYTES,
        },
        reference::indcpa,
    };
    use rand::{rngs::StdRng, RngCore, SeedableRng};
    use std::{
        collections::BTreeSet,
        env, fs,
        path::{Path, PathBuf},
        time::{Duration, Instant},
    };

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Phase {
        Phase1,
        Phase2,
    }

    impl Phase {
        fn as_str(self) -> &'static str {
            match self {
                Phase::Phase1 => "phase1",
                Phase::Phase2 => "phase2",
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Config {
        phase1_bounds: Vec<i128>,
        phase1_trials: usize,
        phase1_early_stop: bool,
        phase2_bounds: Option<Vec<i128>>,
        phase2_trials: Option<usize>,
        phase2_count: usize,
        phase2_early_stop: bool,
        seed: u64,
        csv_out: PathBuf,
        summary_out: PathBuf,
        b_ref_script: Option<i128>,
    }

    #[derive(Debug, Clone)]
    struct BoundResult {
        phase: Phase,
        bound: i128,
        indcpa_failures: usize,
        indcpa_trials_run: usize,
        indcpa_first_failure: Option<usize>,
        kem_failures: usize,
        kem_trials_run: usize,
        kem_first_failure: Option<usize>,
        runtime: Duration,
        stopped_early: bool,
    }

    pub fn run() -> Result<(), String> {
        let config = parse_args()?;
        let b_ref_q = derive_b_ref_q();

        println!("== epp reliability sweep ==");
        println!("params: N={}, k={}, q={}", KYBER_N, KYBER_K, KYBER_Q);
        println!(
            "default epp bound: {} | B_ref_q=floor(q/4)-2Nk={}",
            KYBER_EPP_UNIFORM_BOUND, b_ref_q
        );
        if let Some(b_ref_script) = config.b_ref_script {
            println!("B_ref_script (input): {}", b_ref_script);
        }

        let mut all_results = Vec::new();

        println!(
            "\n[phase1] bounds={} trials={} early_stop={}",
            join_bounds(&config.phase1_bounds),
            config.phase1_trials,
            config.phase1_early_stop
        );
        let mut phase1_results = Vec::new();
        for &bound in &config.phase1_bounds {
            let result = run_bound(
                Phase::Phase1,
                bound,
                config.phase1_trials,
                config.seed,
                config.phase1_early_stop,
            )?;
            print_result_line(&result);
            phase1_results.push(result.clone());
            all_results.push(result);
        }

        let mut phase2_used = Vec::new();
        if let Some(phase2_trials) = config.phase2_trials {
            let selected = if let Some(bounds) = config.phase2_bounds.clone() {
                bounds
            } else {
                select_phase2_bounds(&phase1_results, config.phase2_count)
            };

            if selected.is_empty() {
                println!("\n[phase2] skipped (no candidate bounds selected)");
            } else {
                phase2_used = selected;
                println!(
                    "\n[phase2] bounds={} trials={} early_stop={}",
                    join_bounds(&phase2_used),
                    phase2_trials,
                    config.phase2_early_stop
                );
                for &bound in &phase2_used {
                    let result = run_bound(
                        Phase::Phase2,
                        bound,
                        phase2_trials,
                        config.seed ^ 0xA5A5_A5A5_5A5A_5A5A,
                        config.phase2_early_stop,
                    )?;
                    print_result_line(&result);
                    all_results.push(result);
                }
            }
        }

        write_csv(&config.csv_out, &all_results)?;
        write_summary(
            &config.summary_out,
            &config,
            &all_results,
            &phase2_used,
            b_ref_q,
        )?;

        println!(
            "\nArtifacts written:\n  CSV: {}\n  Summary: {}",
            config.csv_out.display(),
            config.summary_out.display()
        );
        Ok(())
    }

    fn run_bound(
        phase: Phase,
        bound: i128,
        trials: usize,
        base_seed: u64,
        early_stop: bool,
    ) -> Result<BoundResult, String> {
        let mut indcpa_failures = 0usize;
        let mut kem_failures = 0usize;
        let mut indcpa_first_failure = None;
        let mut kem_first_failure = None;
        let mut trials_run = 0usize;
        let start = Instant::now();
        let mut stopped_early = false;

        for trial in 0..trials {
            trials_run += 1;

            if !run_indcpa_trial(base_seed, bound, trial as u64)? {
                indcpa_failures += 1;
                if indcpa_first_failure.is_none() {
                    indcpa_first_failure = Some(trial);
                }
            }

            if !run_kem_trial(base_seed, bound, trial as u64)? {
                kem_failures += 1;
                if kem_first_failure.is_none() {
                    kem_first_failure = Some(trial);
                }
            }

            if early_stop && (indcpa_failures > 0 || kem_failures > 0) {
                stopped_early = true;
                break;
            }
        }

        Ok(BoundResult {
            phase,
            bound,
            indcpa_failures,
            indcpa_trials_run: trials_run,
            indcpa_first_failure,
            kem_failures,
            kem_trials_run: trials_run,
            kem_first_failure,
            runtime: start.elapsed(),
            stopped_early,
        })
    }

    fn run_indcpa_trial(base_seed: u64, bound: i128, trial: u64) -> Result<bool, String> {
        let mut rng =
            StdRng::seed_from_u64(mix_seed(base_seed, bound, trial, 0x494E_4443_5041_0001));
        let mut pk = [0u8; KYBER_INDCPA_PUBLICKEYBYTES];
        let mut sk = [0u8; KYBER_INDCPA_SECRETKEYBYTES];
        indcpa::indcpa_keypair(&mut pk, &mut sk, None, &mut rng).map_err(|e| {
            format!(
                "INDCPA keypair failed at B={} trial={}: {:?}",
                bound, trial, e
            )
        })?;

        let mut m = [0u8; KYBER_SYMBYTES];
        let mut coins = [0u8; KYBER_SYMBYTES];
        rng.fill_bytes(&mut m);
        rng.fill_bytes(&mut coins);

        let mut c = [0u8; KYBER_INDCPA_BYTES];
        indcpa::indcpa_enc_with_epp_bound(&mut c, &m, &pk, &coins, bound);

        let mut m_dec = [0u8; KYBER_SYMBYTES];
        indcpa::indcpa_dec(&mut m_dec, &c, &sk);
        Ok(m == m_dec)
    }

    fn run_kem_trial(base_seed: u64, bound: i128, trial: u64) -> Result<bool, String> {
        let mut rng =
            StdRng::seed_from_u64(mix_seed(base_seed, bound, trial, 0x4B45_4D5F_0000_0002));
        let keys = keypair(&mut rng)
            .map_err(|e| format!("KEM keypair failed at B={} trial={}: {:?}", bound, trial, e))?;
        let (ct, ss1) = encapsulate_with_epp_bound(&keys.public, &mut rng, bound).map_err(|e| {
            format!(
                "KEM encapsulate failed at B={} trial={}: {:?}",
                bound, trial, e
            )
        })?;
        let ss2 = decapsulate_with_epp_bound(&ct, &keys.secret, bound).map_err(|e| {
            format!(
                "KEM decapsulate failed at B={} trial={}: {:?}",
                bound, trial, e
            )
        })?;
        Ok(ss1 == ss2)
    }

    fn mix_seed(base: u64, bound: i128, trial: u64, lane: u64) -> u64 {
        let bound_bits = bound as u128;
        let folded = (bound_bits as u64) ^ ((bound_bits >> 64) as u64);

        base.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ folded.wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
            ^ trial.wrapping_mul(0x1656_67B1_9E37_79F9)
            ^ lane.wrapping_mul(0x85EB_CA77_C2B2_AE63)
    }

    fn select_phase2_bounds(phase1_results: &[BoundResult], count: usize) -> Vec<i128> {
        if count == 0 {
            return Vec::new();
        }

        let mut candidates = phase1_results
            .iter()
            .map(|r| r.bound)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }

        let largest_zero = phase1_results
            .iter()
            .filter(|r| r.indcpa_failures == 0 && r.kem_failures == 0)
            .map(|r| r.bound)
            .max();
        let first_failure = phase1_results
            .iter()
            .filter(|r| r.indcpa_failures > 0 || r.kem_failures > 0)
            .map(|r| r.bound)
            .min();

        let center = first_failure
            .or(largest_zero)
            .unwrap_or_else(|| *candidates.last().unwrap());

        candidates.sort_by_key(|b| (abs_diff_i128(*b, center), *b));
        let mut selected = candidates.into_iter().take(count).collect::<Vec<_>>();
        selected.sort_unstable();
        selected
    }

    fn abs_diff_i128(a: i128, b: i128) -> i128 {
        if a >= b {
            a - b
        } else {
            b - a
        }
    }

    fn derive_b_ref_q() -> i128 {
        let quarter_q = (KYBER_Q / 4) as i128;
        quarter_q - 2 * (KYBER_N as i128) * (KYBER_K as i128)
    }

    fn default_phase1_bounds(b_ref_q: i128, b_ref_script: Option<i128>) -> Vec<i128> {
        let mut bounds = vec![16, 20, 24, 32];

        let mut p = 64i128;
        while p > 0 && p < b_ref_q {
            bounds.push(p);
            if p > i128::MAX / 2 {
                break;
            }
            p *= 2;
        }

        bounds.push(b_ref_q);
        for d in [2i128, 4, 8, 16, 32] {
            let v = b_ref_q / d;
            if v > 0 {
                bounds.push(v);
            }
        }

        if let Some(b_script) = b_ref_script {
            bounds.push(b_script);
            for d in [2i128, 4, 8, 16, 32] {
                let v = b_script / d;
                if v > 0 {
                    bounds.push(v);
                }
            }
        }

        normalize_bounds(bounds)
    }

    fn normalize_bounds(bounds: Vec<i128>) -> Vec<i128> {
        bounds
            .into_iter()
            .filter(|b| *b > 0)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    }

    fn write_csv(path: &Path, results: &[BoundResult]) -> Result<(), String> {
        create_parent_dir(path)?;

        let mut out = String::new();
        out.push_str("phase,bound,indcpa_failures,indcpa_trials,indcpa_first_failure,kem_failures,kem_trials,kem_first_failure,runtime_ms,stopped_early\n");
        for r in results {
            out.push_str(&format!(
                "{},{},{},{},{},{},{},{},{},{}\n",
                r.phase.as_str(),
                r.bound,
                r.indcpa_failures,
                r.indcpa_trials_run,
                option_to_csv(r.indcpa_first_failure),
                r.kem_failures,
                r.kem_trials_run,
                option_to_csv(r.kem_first_failure),
                r.runtime.as_millis(),
                r.stopped_early
            ));
        }

        fs::write(path, out).map_err(|e| format!("failed writing {}: {}", path.display(), e))
    }

    fn option_to_csv(v: Option<usize>) -> String {
        match v {
            Some(x) => x.to_string(),
            None => String::new(),
        }
    }

    fn write_summary(
        path: &Path,
        config: &Config,
        results: &[BoundResult],
        phase2_used: &[i128],
        b_ref_q: i128,
    ) -> Result<(), String> {
        create_parent_dir(path)?;

        let largest_zero = largest_zero_failure_bound(results);
        let first_failure = first_failure_bound(results);
        let recommendation = recommendation_for(largest_zero, first_failure, b_ref_q);

        let mut sorted = results.to_vec();
        sorted.sort_by_key(|r| (r.phase.as_str().to_string(), r.bound));

        let mut md = String::new();
        md.push_str("# epp Reliability Sweep Summary\n\n");
        md.push_str("## Setup\n");
        md.push_str(&format!(
            "- Parameters: `N={}`, `k={}`, `q={}`\n",
            KYBER_N, KYBER_K, KYBER_Q
        ));
        md.push_str(&format!(
            "- Default bound (`KYBER_EPP_UNIFORM_BOUND`): `{}`\n",
            KYBER_EPP_UNIFORM_BOUND
        ));
        md.push_str(&format!("- `B_ref_q = floor(q/4)-2Nk`: `{}`\n", b_ref_q));
        if let Some(b_ref_script) = config.b_ref_script {
            md.push_str(&format!(
                "- `B_ref_script` (provided): `{}`\n",
                b_ref_script
            ));
        }
        md.push_str(&format!(
            "- Phase 1: bounds=`{}`, trials={}, early_stop={}\n",
            join_bounds(&config.phase1_bounds),
            config.phase1_trials,
            config.phase1_early_stop
        ));
        if let Some(phase2_trials) = config.phase2_trials {
            if phase2_used.is_empty() {
                md.push_str("- Phase 2: skipped (no selected bounds)\n");
            } else {
                md.push_str(&format!(
                    "- Phase 2: bounds=`{}`, trials={}, early_stop={}\n",
                    join_bounds(phase2_used),
                    phase2_trials,
                    config.phase2_early_stop
                ));
            }
        } else {
            md.push_str("- Phase 2: not requested\n");
        }

        md.push_str("\n## Results\n");
        md.push_str("| Phase | Bound B | INDCPA failures/trials | KEM failures/trials | First INDCPA fail | First KEM fail | Runtime (ms) | Early stop |\n");
        md.push_str("|---|---:|---:|---:|---:|---:|---:|---|\n");
        for r in &sorted {
            md.push_str(&format!(
                "| {} | {} | {}/{} | {}/{} | {} | {} | {} | {} |\n",
                r.phase.as_str(),
                r.bound,
                r.indcpa_failures,
                r.indcpa_trials_run,
                r.kem_failures,
                r.kem_trials_run,
                r.indcpa_first_failure
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.kem_first_failure
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "-".to_string()),
                r.runtime.as_millis(),
                r.stopped_early
            ));
        }

        md.push_str("\n## Decision Signals\n");
        md.push_str(&format!(
            "- Largest zero-failure bound observed: `{}`\n",
            largest_zero
                .map(|x| x.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        md.push_str(&format!(
            "- First failing bound observed: `{}`\n",
            first_failure
                .map(|x| x.to_string())
                .unwrap_or_else(|| "none".to_string())
        ));
        md.push_str(&format!(
            "- Recommended next action: **{}**\n",
            recommendation
        ));

        fs::write(path, md).map_err(|e| format!("failed writing {}: {}", path.display(), e))
    }

    fn largest_zero_failure_bound(results: &[BoundResult]) -> Option<i128> {
        results
            .iter()
            .filter(|r| r.indcpa_failures == 0 && r.kem_failures == 0)
            .map(|r| r.bound)
            .max()
    }

    fn first_failure_bound(results: &[BoundResult]) -> Option<i128> {
        results
            .iter()
            .filter(|r| r.indcpa_failures > 0 || r.kem_failures > 0)
            .map(|r| r.bound)
            .min()
    }

    fn recommendation_for(
        largest_zero: Option<i128>,
        first_failure: Option<i128>,
        b_ref_q: i128,
    ) -> &'static str {
        if first_failure.is_none() {
            return "try larger B";
        }

        let lz = match largest_zero {
            Some(v) => v,
            None => return "keep small B",
        };

        if lz <= KYBER_EPP_UNIFORM_BOUND {
            return "keep small B";
        }

        if lz < (b_ref_q / 8).max(KYBER_EPP_UNIFORM_BOUND * 2) {
            return "re-parameterize";
        }

        "try larger B"
    }

    fn print_result_line(result: &BoundResult) {
        println!(
            "  {} B={}: indcpa {}/{} (first={}), kem {}/{} (first={}), {} ms{}",
            result.phase.as_str(),
            result.bound,
            result.indcpa_failures,
            result.indcpa_trials_run,
            result
                .indcpa_first_failure
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".to_string()),
            result.kem_failures,
            result.kem_trials_run,
            result
                .kem_first_failure
                .map(|x| x.to_string())
                .unwrap_or_else(|| "-".to_string()),
            result.runtime.as_millis(),
            if result.stopped_early {
                " (early-stop)"
            } else {
                ""
            }
        );
    }

    fn join_bounds(bounds: &[i128]) -> String {
        bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }

    fn create_parent_dir(path: &Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("failed creating {}: {}", parent.display(), e))?;
            }
        }
        Ok(())
    }

    fn parse_args() -> Result<Config, String> {
        let mut phase1_bounds = None;
        let mut phase1_trials = 2_000usize;
        let mut phase1_early_stop = true;
        let mut phase2_bounds = None;
        let mut phase2_trials = None;
        let mut phase2_count = 5usize;
        let mut phase2_early_stop = false;
        let mut seed = 0x5EED_5EED_1234_5678u64;
        let mut csv_out = PathBuf::from("target/epp_reliability_sweep.csv");
        let mut summary_out = PathBuf::from("target/epp_reliability_summary.md");
        let mut b_ref_script = None;

        let mut args = env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_help();
                    std::process::exit(0);
                }
                "--phase1-bounds" => {
                    phase1_bounds = Some(parse_i128_list(&next_value(&mut args, &arg)?)?);
                }
                "--phase1-trials" => {
                    phase1_trials = parse_usize(&next_value(&mut args, &arg)?, &arg)?;
                }
                "--phase1-early-stop" => {
                    phase1_early_stop = parse_bool(&next_value(&mut args, &arg)?, &arg)?;
                }
                "--phase2-bounds" => {
                    phase2_bounds = Some(parse_i128_list(&next_value(&mut args, &arg)?)?);
                }
                "--phase2-trials" => {
                    phase2_trials = Some(parse_usize(&next_value(&mut args, &arg)?, &arg)?);
                }
                "--phase2-count" => {
                    phase2_count = parse_usize(&next_value(&mut args, &arg)?, &arg)?;
                }
                "--phase2-early-stop" => {
                    phase2_early_stop = parse_bool(&next_value(&mut args, &arg)?, &arg)?;
                }
                "--seed" => {
                    seed = parse_u64(&next_value(&mut args, &arg)?, &arg)?;
                }
                "--csv-out" => {
                    csv_out = PathBuf::from(next_value(&mut args, &arg)?);
                }
                "--summary-out" => {
                    summary_out = PathBuf::from(next_value(&mut args, &arg)?);
                }
                "--b-ref-script" => {
                    b_ref_script = Some(parse_i128(&next_value(&mut args, &arg)?, &arg)?);
                }
                _ => return Err(format!("unknown argument: {arg}")),
            }
        }

        if phase2_trials.is_some() && phase2_count == 0 {
            return Err("--phase2-count must be > 0 when --phase2-trials is set".to_string());
        }

        let b_ref_q = derive_b_ref_q();
        let phase1_bounds = normalize_bounds(match phase1_bounds {
            Some(v) => v,
            None => default_phase1_bounds(b_ref_q, b_ref_script),
        });

        if phase1_bounds.is_empty() {
            return Err("phase1 bounds are empty after normalization".to_string());
        }

        let phase2_bounds = phase2_bounds
            .map(normalize_bounds)
            .filter(|v| !v.is_empty());

        Ok(Config {
            phase1_bounds,
            phase1_trials,
            phase1_early_stop,
            phase2_bounds,
            phase2_trials,
            phase2_count,
            phase2_early_stop,
            seed,
            csv_out,
            summary_out,
            b_ref_script,
        })
    }

    fn parse_i128_list(s: &str) -> Result<Vec<i128>, String> {
        let mut out = Vec::new();
        for raw in s.split(',') {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            out.push(parse_i128(item, "list-item")?);
        }
        if out.is_empty() {
            return Err("expected a non-empty comma-separated list".to_string());
        }
        Ok(out)
    }

    fn parse_i128(s: &str, flag: &str) -> Result<i128, String> {
        s.parse::<i128>()
            .map_err(|_| format!("invalid i128 for {}: {}", flag, s))
    }

    fn parse_u64(s: &str, flag: &str) -> Result<u64, String> {
        s.parse::<u64>()
            .map_err(|_| format!("invalid u64 for {}: {}", flag, s))
    }

    fn parse_usize(s: &str, flag: &str) -> Result<usize, String> {
        s.parse::<usize>()
            .map_err(|_| format!("invalid usize for {}: {}", flag, s))
    }

    fn parse_bool(s: &str, flag: &str) -> Result<bool, String> {
        match s {
            "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
            "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
            _ => Err(format!("invalid bool for {}: {}", flag, s)),
        }
    }

    fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
        args.next()
            .ok_or_else(|| format!("missing value for {}", flag))
    }

    fn print_help() {
        println!(
            "Usage:\n\
             cargo run --release --example epp_reliability_sweep --features hazmat -- [options]\n\n\
             Options:\n\
               --phase1-bounds <csv_i128>      Optional. Defaults to an auto-generated coarse set.\n\
               --phase1-trials <usize>          Default: 2000\n\
               --phase1-early-stop <bool>       Default: true\n\
               --phase2-trials <usize>          Optional. Enables phase2 when provided.\n\
               --phase2-bounds <csv_i128>       Optional explicit phase2 list.\n\
               --phase2-count <usize>           Auto-select count if --phase2-bounds not set (default 5).\n\
               --phase2-early-stop <bool>       Default: false\n\
               --seed <u64>                     Default: 0x5EED5EED12345678\n\
               --csv-out <path>                 Default: target/epp_reliability_sweep.csv\n\
               --summary-out <path>             Default: target/epp_reliability_summary.md\n\
               --b-ref-script <i128>            Optional script/theory reference bound for reporting.\n"
        );
    }
}

#[cfg(feature = "hazmat")]
fn main() {
    if let Err(err) = app::run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}
