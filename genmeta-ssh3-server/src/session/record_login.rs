use nix::{libc, unistd};

// Linux utmp相关结构体定义
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExitStatus {
    e_termination: libc::c_short, // 进程终止状态
    e_exit: libc::c_short,        // 进程退出状态
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Utmp {
    ut_type: libc::c_short,               // 类型 (USER_PROCESS = 7)
    ut_pid: libc::pid_t,                  // 进程ID
    ut_line: [libc::c_char; 32],          // 终端线
    ut_id: [libc::c_char; 4],             // 终端ID
    ut_user: [libc::c_char; 32],          // 用户名
    ut_host: [libc::c_char; 256],         // 主机名
    ut_exit: ExitStatus,                  // 退出状态
    ut_session: libc::c_long,             // 会话ID
    ut_tv: libc::timeval,                 // 时间戳
    ut_addr_v6: [libc::c_int; 4],         // IPv6地址
    __glibc_reserved: [libc::c_char; 20], // 保留
}

impl Default for Utmp {
    fn default() -> Self {
        Self {
            ut_type: libc::USER_PROCESS as libc::c_short,
            ut_pid: std::process::id() as libc::pid_t,
            ut_line: [0; 32],
            ut_id: [0; 4],
            ut_user: [0; 32],
            ut_host: [0; 256],
            ut_exit: ExitStatus::default(),
            ut_session: std::process::id() as libc::c_long,
            ut_tv: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ut_addr_v6: [0; 4],
            __glibc_reserved: [0; 20],
        }
    }
}

/// 安全地将Rust字符串复制到C风格的字符数组中
fn copy_string_to_c_array(src: &str, dest: &mut [libc::c_char]) {
    let bytes = src.as_bytes();
    let len = bytes.len().min(dest.len().saturating_sub(1)); // 留一个位置给null终止符

    // 复制字符
    for (i, &b) in bytes.iter().take(len).enumerate() {
        dest[i] = b as libc::c_char;
    }

    // 确保null终止（虽然数组已经初始化为0，但为了明确起见）
    if len < dest.len() {
        dest[len] = 0;
    }
}

/// 记录登录会话到系统日志
pub fn record_login(clientname: &str, user: &unistd::User) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    // 记录到tracing日志
    tracing::info!(
        target: "login",
        "User {} logged in from {} (uid={}, gid={})",
        user.name, clientname, user.uid, user.gid
    );

    // 尝试写入系统日志文件（类似OpenSSH的做法）
    // 在Linux系统上，通常写入 /var/log/auth.log 或使用syslog
    let log_result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/auth.log")?;

        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = duration.as_secs();

        // 使用简单的ctime格式
        let timestamp = format!("{}", secs);

        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::fs::read_to_string("/proc/sys/kernel/hostname"))
            .unwrap_or_else(|_| "localhost".to_string())
            .trim()
            .to_string();

        let log_entry = format!(
            "{} {} sshd3[{}]: Accepted session for {} from {} port {} ssh3\n",
            timestamp,
            hostname,
            std::process::id(),
            user.name,
            clientname,
            "unknown"
        );

        file.write_all(log_entry.as_bytes())?;
        file.flush()?;
        Ok(())
    })();

    if let Err(e) = log_result {
        tracing::warn!(target: "login", "Failed to write to auth.log: {}", e);
    }

    // 尝试写入utmp和wtmp文件（模仿OpenSSH的loginrec.c）
    write_utmp_entry(clientname, user);
    write_wtmp_entry(clientname, user);

    // TODO: 更新lastlog文件
    // 这需要写入lastlog结构到/var/log/lastlog
}

/// 写入utmp记录（当前登录会话）
pub fn write_utmp_entry(clientname: &str, user: &unistd::User) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem;
    use std::time::{SystemTime, UNIX_EPOCH};

    // 在Linux上，utmp结构定义在utmp.h中
    // 我们需要构造一个utmp条目并写入/var/run/utmp

    let mut utmp_entry = Utmp::default();

    // 设置用户名（安全地复制字符串到C数组）
    copy_string_to_c_array(&user.name, &mut utmp_entry.ut_user);

    // 设置主机名
    copy_string_to_c_array(clientname, &mut utmp_entry.ut_host);

    // 设置时间戳
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    utmp_entry.ut_tv.tv_sec = duration.as_secs() as libc::time_t;
    utmp_entry.ut_tv.tv_usec = duration.subsec_micros() as libc::suseconds_t;

    // 使用安全的Rust文件API写入utmp文件
    let utmp_result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/run/utmp")?;

        // 将结构体转换为字节数组并写入
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &utmp_entry as *const Utmp as *const u8,
                mem::size_of::<Utmp>(),
            )
        };
        file.write_all(bytes)?;
        file.flush()?;
        Ok(())
    })();

    if let Err(e) = utmp_result {
        tracing::warn!(target: "login", "Failed to write to utmp: {}", e);
    }
}

/// 写入wtmp记录（登录历史）
pub fn write_wtmp_entry(clientname: &str, user: &unistd::User) {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::mem;
    use std::time::{SystemTime, UNIX_EPOCH};

    let mut wtmp_entry = Utmp::default();

    // 设置用户名
    copy_string_to_c_array(&user.name, &mut wtmp_entry.ut_user);

    // 设置主机名
    copy_string_to_c_array(clientname, &mut wtmp_entry.ut_host);

    // 设置时间戳
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    wtmp_entry.ut_tv.tv_sec = duration.as_secs() as libc::time_t;
    wtmp_entry.ut_tv.tv_usec = duration.subsec_micros() as libc::suseconds_t;

    // 使用安全的Rust文件API写入wtmp文件
    let wtmp_result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("/var/log/wtmp")?;

        // 将结构体转换为字节数组并写入
        let bytes = unsafe {
            std::slice::from_raw_parts(
                &wtmp_entry as *const Utmp as *const u8,
                mem::size_of::<Utmp>(),
            )
        };
        file.write_all(bytes)?;
        file.flush()?;
        Ok(())
    })();

    if let Err(e) = wtmp_result {
        tracing::warn!(target: "login", "Failed to write to wtmp: {}", e);
    }
}
