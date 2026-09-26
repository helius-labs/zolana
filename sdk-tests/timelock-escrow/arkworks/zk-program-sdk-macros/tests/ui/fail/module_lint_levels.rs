use zk_program_sdk::circuit;

#[circuit]
mod levels {
    pub fn unused() {
        let ignored = 1u64;
    }

    pub fn unchecked() -> u64 {
        unsafe { core::hint::unreachable_unchecked() }
    }
}

fn main() {
    levels::unused();
    assert_eq!(levels::unchecked(), 0);
}
