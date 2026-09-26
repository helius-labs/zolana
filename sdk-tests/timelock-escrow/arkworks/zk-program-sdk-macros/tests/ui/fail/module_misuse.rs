use zk_program_sdk::circuit;

#[circuit]
mod twice {
    #[circuit]
    fn inner() {}

    mod nested {
        #[zk_program_sdk::circuit]
        impl Nested {}
    }
}

#[circuit]
mod projection {
    impl <u8 as Clone>::Target {}

    impl [u8; 4] {}
}

fn main() {}
