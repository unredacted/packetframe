//! Smoke checks for the VPP sampler plugin, run by CI's arm64 VPP job
//! (`crates/vpp-plugins/pf-sampler/ci/smoke.sh`) against a real VPP. Not
//! the lab reader: that is `packetframe` itself (plan step 0.4).
//!
//! ```text
//! sampler-smoke desired <generation> <rate> <header-bytes> <interface>...
//! sampler-smoke wait-applied <generation> <timeout-s>
//! sampler-smoke drain <interface> <packets> <rate> <frame-len> <dst-mac> <timeout-s>
//! ```
//!
//! The directory is `PF_SAMPLER_DIR`, as for the plugin.

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    linux::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("sampler-smoke runs on Linux only");
}

#[cfg(target_os = "linux")]
mod linux {
    use std::process::ExitCode;
    use std::time::{Duration, Instant};

    use packetframe_sampler_core::driver::sampler_dir;
    use packetframe_sampler_shm::desired::Desired;
    use packetframe_sampler_shm::fs::{
        open_epoch, write_atomic, Lock, CONSUMER_LOCK, DESIRED, DESIRED_LOCK,
    };
    use packetframe_sampler_shm::status::State;
    use packetframe_sampler_shm::Class;

    pub fn main() -> ExitCode {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let r = match args.first().map(String::as_str) {
            Some("desired") => desired(&args[1..]),
            Some("wait-applied") => wait_applied(&args[1..]),
            Some("drain") => drain(&args[1..]),
            _ => Err("usage: sampler-smoke desired|wait-applied|drain ...".into()),
        };
        match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("sampler-smoke: FAIL: {e}");
                ExitCode::FAILURE
            }
        }
    }

    fn arg<T: std::str::FromStr>(a: &[String], i: usize, what: &str) -> Result<T, String> {
        a.get(i)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("missing or bad {what}"))
    }

    fn desired(a: &[String]) -> Result<(), String> {
        let dir = sampler_dir()?;
        let d = Desired {
            generation: arg(a, 0, "generation")?,
            rate: arg(a, 1, "rate")?,
            header_bytes: arg(a, 2, "header-bytes")?,
            classes: Class::Ingress.bit(),
            interfaces: a[3..].to_vec(),
        };
        let _lock = Lock::try_exclusive(&dir.join(DESIRED_LOCK))
            .map_err(|e| e.to_string())?
            .ok_or("desired.lock is held")?;
        write_atomic(&dir, DESIRED, d.render().as_bytes()).map_err(|e| e.to_string())?;
        println!("desired generation {} written", d.generation);
        Ok(())
    }

    fn wait_applied(a: &[String]) -> Result<(), String> {
        let dir = sampler_dir()?;
        let generation: u64 = arg(a, 0, "generation")?;
        let deadline = Instant::now() + Duration::from_secs(arg(a, 1, "timeout")?);
        let mut last = String::from("no epoch yet");
        while Instant::now() < deadline {
            if let Ok(o) = open_epoch(&dir, false) {
                match o.status().read() {
                    Ok(s) => {
                        let resolved = s.interfaces.iter().all(|i| i.sw_if_index.is_some());
                        if s.state == State::Enabled
                            && s.applied_generation == generation
                            && resolved
                        {
                            println!("applied: {s:?}");
                            return Ok(());
                        }
                        last = format!("{s:?}");
                    }
                    Err(e) => last = e.to_string(),
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(format!(
            "generation {generation} not applied; last status {last}"
        ))
    }

    fn drain(a: &[String]) -> Result<(), String> {
        let dir = sampler_dir()?;
        let iface: String = arg(a, 0, "interface")?;
        let packets: u64 = arg(a, 1, "packets")?;
        let rate: u32 = arg(a, 2, "rate")?;
        let frame_len: u32 = arg(a, 3, "frame-len")?;
        let mac: Vec<u8> = a
            .get(4)
            .ok_or("missing dst-mac")?
            .split(':')
            .map(|h| u8::from_str_radix(h, 16).map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        let deadline = Instant::now() + Duration::from_secs(arg(a, 5, "timeout")?);

        let _lock = Lock::try_exclusive(&dir.join(CONSUMER_LOCK))
            .map_err(|e| e.to_string())?
            .ok_or("another consumer holds consumer.lock")?;
        let o = open_epoch(&dir, true).map_err(|e| e.to_string())?;
        let s = o.status().read().map_err(|e| e.to_string())?;
        let i = s
            .interfaces
            .iter()
            .find(|i| i.name == iface)
            .ok_or(format!("{iface} is not configured"))?;
        let sw = i.sw_if_index.ok_or(format!("{iface} is unresolved"))?;
        let pool = usize::from(i.pool_index);
        let workers = o.layout().workers;

        let mut samples = Vec::new();
        let (mut corrupt, mut skipped) = (0, 0);
        let seen = |o: &packetframe_sampler_shm::fs::Opened| -> u64 {
            (0..workers)
                .map(|r| o.ring(r).unwrap().counters().pool[pool][Class::Ingress.index()])
                .sum()
        };
        loop {
            for r in 0..workers {
                let d = o.ring(r).unwrap().drain(&mut samples, usize::MAX);
                corrupt += d.corrupt;
                skipped += d.skipped;
            }
            let queued: u64 = (0..workers)
                .map(|r| {
                    let c = o.ring(r).unwrap().counters();
                    c.head.wrapping_sub(c.tail)
                })
                .sum();
            if seen(&o) >= packets && queued == 0 {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "timed out: pool {} of {packets}, {} samples so far",
                    seen(&o),
                    samples.len()
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let (mut selected, mut written, mut dropped) = (0, 0, 0);
        for r in 0..workers {
            let c = o.ring(r).unwrap().counters();
            println!(
                "ring {r}: pool {} selected {} written {} dropped-full {}",
                c.pool[pool][Class::Ingress.index()],
                c.selected,
                c.written,
                c.dropped_full
            );
            if c.selected != c.written + c.dropped_full {
                return Err(format!("ring {r}: selected != written + dropped-full"));
            }
            selected += c.selected;
            written += c.written;
            dropped += c.dropped_full;
        }
        let pool_total = seen(&o);
        println!(
            "pool {pool_total}, selected {selected}, written {written}, dropped {dropped}, \
             drained {}, corrupt {corrupt}, skipped {skipped}",
            samples.len()
        );
        if pool_total != packets {
            return Err(format!("pool counted {pool_total} packets, sent {packets}"));
        }
        if (corrupt, skipped) != (0, 0) || samples.len() as u64 != written {
            return Err("drained samples disagree with the producer's counts".into());
        }
        let expected = packets as f64 / f64::from(rate);
        let tolerance = 5.0 * expected.sqrt() + 1.0;
        if (selected as f64 - expected).abs() > tolerance {
            return Err(format!(
                "selected {selected}, expected {expected:.0} ± {tolerance:.0}"
            ));
        }
        let want_len = (s.header_bytes.min(frame_len)) as usize;
        for x in &samples {
            let m = &x.meta;
            if m.generation != s.applied_generation
                || m.rate != rate
                || m.sw_if_index != sw
                || usize::from(m.pool_index) != pool
                || m.frame_len != frame_len
                || x.header.len() != want_len
                || !x.header.starts_with(&mac)
            {
                return Err(format!("unexpected sample {x:?}"));
            }
        }
        println!("ok: {} samples checked", samples.len());
        Ok(())
    }
}
