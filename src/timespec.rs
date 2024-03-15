pub use libc::timespec;
use libc::{self, CLOCK_BOOTTIME};

pub fn timespec_sub(ts1: timespec, ts2: timespec) -> timespec {
    let mut ts3 = timespec {
        tv_sec: ts1.tv_sec - ts2.tv_sec,
        tv_nsec: ts1.tv_nsec - ts2.tv_nsec,
    };

    while ts3.tv_nsec < 0 {
        ts3.tv_sec -= 1;
        ts3.tv_nsec += 1000000000;
    }
    return ts3;
}

pub fn timespec_now() -> Result<timespec, String> {
    let mut ts = Box::new(timespec {
        tv_sec: 0,
        tv_nsec: 0,
    });
    let status = unsafe { libc::clock_gettime(CLOCK_BOOTTIME, &mut *ts) };

    if status != 0 {
        return Err(format!(
            "Unable to get current time. Error code: {}",
            status
        ));
    }

    return Ok(*ts);
}
