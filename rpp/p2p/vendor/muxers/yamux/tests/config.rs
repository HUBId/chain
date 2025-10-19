use std::time::Duration;

use libp2p_yamux::Config;

#[test]
fn default_config_matches_rpp_values() {
    let cfg = Config::default();
    assert_eq!(cfg.max_connection_receive_window(), Some(128 * 1024 * 1024));
    assert_eq!(cfg.max_num_streams(), 512);
    assert_eq!(cfg.max_buffer_size(), 4 * 1024 * 1024);
    assert_eq!(cfg.max_frame_data_len(), 256 * 1024);
    assert!(!cfg.read_after_close());
    assert_eq!(cfg.keepalive_interval(), Duration::from_secs(5));
}

#[test]
fn setters_apply_customizations() {
    let mut cfg = Config::default();
    cfg.set_max_connection_receive_window(Some(256 * 1024 * 1024))
        .set_max_num_streams(256)
        .set_max_frame_data_len(128 * 1024)
        .set_max_buffer_size(128 * 1024)
        .set_split_send_size(32 * 1024)
        .set_keepalive_interval(Duration::from_secs(2));

    assert_eq!(cfg.max_connection_receive_window(), Some(256 * 1024 * 1024));
    assert_eq!(cfg.max_num_streams(), 256);
    assert_eq!(cfg.max_frame_data_len(), 128 * 1024);
    assert_eq!(cfg.max_buffer_size(), 128 * 1024);
    assert_eq!(cfg.keepalive_interval(), Duration::from_secs(2));
}
