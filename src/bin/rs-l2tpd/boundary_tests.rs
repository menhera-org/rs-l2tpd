use super::*;

/// spec: P16, P24, L11
#[test]
fn service_and_host_failures_preserve_exit_status_priority() {
    for (result, expected) in [
        (Ok(()), 0),
        (Err(rs_l2tpd::Error::ReloadPanicked), 2),
        (Err(rs_l2tpd::Error::RestartPanicked), 2),
        (
            Err(rs_l2tpd::Error::Other("controlled service error".into())),
            1,
        ),
    ] {
        let code = service_status(result);
        assert_eq!(code, expected);
        assert_eq!(host_status(code, Ok(())), expected);
        assert_eq!(host_status(code, Err(Box::new("controlled host panic"))), 1);
    }
}

/// spec: P14, L8, L13, G14
#[test]
fn a_host_receiver_can_be_taken_once_and_absence_is_an_error() {
    let mut service = Service::with_kernel(
        rs_l2tpd::config::Config::new(),
        rs_l2tpd::kernel::fake::FakeKernel::new(42),
        Box::new(rs_l2tpd::reconciler::IphostResolve::default()),
        vec![],
    )
    .map_err(|(error, _)| error)
    .unwrap();
    let receiver = host_requests(&mut service).unwrap();
    assert_eq!(
        host_requests(&mut service).unwrap_err().to_string(),
        "host receiver unavailable"
    );
    drop(receiver);
    drop(service);
}
