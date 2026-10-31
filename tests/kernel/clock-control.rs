//! H16's host controller. QMP controls only the disposable QEMU child.
//! Protocol: https://www.qemu.org/docs/master/interop/qmp-spec.html
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

fn line(reader: &mut impl BufRead) -> io::Result<Option<String>> {
    let mut bytes = Vec::new();
    reader.take(65537).read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > 65536 || bytes.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "oversized or incomplete control line",
        ));
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

struct Qmp(BufReader<UnixStream>);
impl Qmp {
    fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        let mut qmp = Self(BufReader::new(stream));
        let greeting = qmp.receive(Instant::now() + Duration::from_secs(5))?;
        if !greeting.contains("\"QMP\":{") {
            return Err(io::Error::other("unexpected QMP greeting"));
        }
        qmp.execute("qmp_capabilities", 0)?;
        Ok(qmp)
    }
    fn receive(&mut self, deadline: Instant) -> io::Result<String> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "QMP deadline"))?;
        self.0.get_ref().set_read_timeout(Some(remaining))?;
        let text = line(&mut self.0)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "QMP closed"))?;
        Ok(text.chars().filter(|c| !c.is_ascii_whitespace()).collect())
    }
    fn execute(&mut self, command: &str, id: u32) -> io::Result<String> {
        // shortcut: fixed argument-free commands only; use a JSON parser before adding arbitrary arguments.
        writeln!(
            self.0.get_mut(),
            "{{\"execute\":\"{command}\",\"id\":\"phase6-{id}\"}}"
        )?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let response = self.receive(deadline)?;
            if response.contains("\"event\":") {
                continue;
            }
            if !response.contains(&format!("\"id\":\"phase6-{id}\""))
                || !response.contains("\"return\":")
                || response.contains("\"error\":")
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "failed or mismatched QMP reply",
                ));
            }
            return Ok(response);
        }
    }
    fn state(&mut self, status: &str, running: bool, id: u32) -> io::Result<()> {
        let response = self.execute("query-status", id)?;
        if !response.contains(&format!("\"status\":\"{status}\""))
            || !response.contains(&format!("\"running\":{running}"))
        {
            return Err(io::Error::other(
                "QEMU run state differs from the requested state",
            ));
        }
        println!("H16_QMP_STATE={status}");
        Ok(())
    }
}

#[cfg(not(test))]
struct Guest(std::process::Child);
#[cfg(not(test))]
impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[cfg(not(test))]
fn run() -> io::Result<()> {
    let mut args = std::env::args_os().skip(1);
    let monitor = args
        .next()
        .ok_or_else(|| io::Error::other("usage: clock-control QMP_SOCKET QEMU [ARG... ]"))?;
    let program = args
        .next()
        .ok_or_else(|| io::Error::other("missing QEMU command"))?;
    let mut guest = Guest(
        std::process::Command::new(program)
            .args(args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .spawn()?,
    );
    let mut output = BufReader::new(guest.0.stdout.take().unwrap());
    let mut paused = false;
    while let Some(text) = line(&mut output)? {
        print!("{text}");
        io::stdout().flush()?;
        if text.trim() == "H16_PAUSE_READY" {
            if paused {
                return Err(io::Error::other("duplicate pause request"));
            }
            let mut qmp = Qmp::new(UnixStream::connect(&monitor)?)?;
            qmp.execute("stop", 1)?;
            qmp.state("paused", false, 2)?;
            let stopped = Instant::now();
            // A measured pause is the experimental stimulus, not a readiness sleep.
            std::thread::sleep(Duration::from_secs(3));
            qmp.state("paused", false, 3)?;
            println!("H16_CONTROLLER_PAUSE_NS={}", stopped.elapsed().as_nanos());
            qmp.execute("cont", 4)?;
            qmp.state("running", true, 5)?;
            guest
                .0
                .stdin
                .as_mut()
                .unwrap()
                .write_all(b"H16_RESUMED\n")?;
            paused = true;
        }
    }
    if !guest.0.wait()?.success() || !paused {
        return Err(io::Error::other("QEMU failed or never requested a pause"));
    }
    println!("H16_CONTROLLER_RESULT=0");
    Ok(())
}
#[cfg(not(test))]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("H16_CONTROLLER_ERROR={error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mock(replies: Vec<String>) -> (UnixStream, std::thread::JoinHandle<()>) {
        let (client, server) = UnixStream::pair().unwrap();
        let thread = std::thread::spawn(move || {
            let mut server = BufReader::new(server);
            server
                .get_mut()
                .write_all(b"{\"QMP\": {\"version\": {}, \"capabilities\": []}}\r\n")
                .unwrap();
            for response in replies {
                let request = line(&mut server).unwrap().unwrap();
                assert!(request.contains("\"execute\":") && request.contains("\"id\":\"phase6-"));
                server.get_mut().write_all(response.as_bytes()).unwrap();
            }
        });
        (client, thread)
    }
    #[test]
    fn qmp_accepts_events_and_field_reordering_and_checks_run_state() {
        let (client, server) = mock(vec![
            "{\"event\":\"STOP\"}\n{\"id\":\"phase6-0\", \"return\":{}}\n".into(),
            "{\"return\":{\"running\":false,\"status\":\"paused\"},\"id\":\"phase6-1\"}\n".into(),
            "{\"return\":{\"status\":\"paused\",\"running\":false},\"id\":\"phase6-2\"}\n".into(),
        ]);
        let mut qmp = Qmp::new(client).unwrap();
        qmp.state("paused", false, 1).unwrap();
        assert!(qmp.state("running", true, 2).is_err());
        server.join().unwrap();
    }
    #[test]
    fn qmp_rejects_error_and_wrong_transaction_and_eof() {
        for response in [
            "{\"error\":{},\"id\":\"phase6-0\"}\n",
            "{\"return\":{},\"id\":\"phase6-9\"}\n",
            "",
        ] {
            let (client, server) = mock(vec![response.into()]);
            assert!(Qmp::new(client).is_err());
            server.join().unwrap();
        }
    }
    #[test]
    fn lines_are_bounded_and_complete_and_utf8() {
        assert!(line(&mut io::Cursor::new(vec![b'x'; 65537])).is_err());
        assert!(line(&mut io::Cursor::new(b"partial")).is_err());
        assert!(line(&mut io::Cursor::new([0xff, b'\n'])).is_err());
        assert_eq!(
            line(&mut io::Cursor::new(b"\n")).unwrap(),
            Some("\n".into())
        );
    }
}
